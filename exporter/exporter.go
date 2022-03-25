package exporter

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/cloudflare/ebpf_exporter/decoder"
	"github.com/iovisor/gobpf/bcc"
	"github.com/prometheus/client_golang/prometheus"
)

// Namespace to use for all metrics
// * ebpf_exporter经常会被调用
const prometheusNamespace = "ebpf_exporter"

// Exporter is a ebpf_exporter instance implementing prometheus.Collector
type Exporter struct {
	//配置文件实例化
	config config.Config
	//bcc模块——后面会用到的工具
	//* 数值采集时访问tableID读取
	modules map[string]*bcc.Module
	//? perfMap
	perfMapCollectors []*PerfMapSink
	// * kaddrs是内核内存地址
	kaddrs map[string]uint64
	// * prometheus.Desc是暴露给prometheus指标（Metric）的描述符
	// * enabledProgramsDesc对应项目programe:name
	// * programInfoDesc对应kprobes的函数（value值）
	enabledProgramsDesc *prometheus.Desc
	programInfoDesc     *prometheus.Desc
	// * 对应program的全部ebpf函数(探针的value)的内存地址
	programTags map[string]map[string]uint64
	// * prometheus的度量描述符
	descs    map[string]map[string]*prometheus.Desc
	decoders *decoder.Set
}

// New creates a new exporter with the provided config
func New(cfg config.Config) (*Exporter, error) {
	// * 保证配置文件是一个有效的配置
	// * 必备的元素：1.programes 2.code 3.探针类别
	err := config.ValidateConfig(&cfg)
	if err != nil {
		return nil, fmt.Errorf("error validating config: %s", err)
	}
	// * enabledProgramesDesc和programInfoDesc会被普罗米修斯里的每一个度量使用
	// * 指标描述符是prometheus度量数据所要去找的元数据
	// * 一个新的指标描述符 ，对应起的programes。
	// * 找enabledProgramsDesc度量起的programes
	enabledProgramsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "enabled_programs"),
		"The set of enabled programs",
		[]string{"name"},
		nil,
	)
	// *另一指标描述符，度量每一个ebpf metric的内部信息
	// * 找programInfoDesc度量ebpf programe信息的数据
	//* 有“program”、“function”、“tag”作为labelName
	programInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "ebpf_programs"),
		"Info about ebpf programs",
		[]string{"program", "function", "tag"},
		nil,
	)

	return &Exporter{
		config:              cfg,
		modules:             map[string]*bcc.Module{},
		kaddrs:              map[string]uint64{},
		enabledProgramsDesc: enabledProgramsDesc,
		programInfoDesc:     programInfoDesc,
		programTags:         map[string]map[string]uint64{},
		descs:               map[string]map[string]*prometheus.Desc{},
		decoders:            decoder.NewSet(),
	}, nil
}

// Attach injects eBPF into kernel and attaches necessary kprobes
// * 该函数Exporter
// * 进入这个函数前config配置文件已经转义
func (e *Exporter) Attach() error {
	for _, program := range e.config.Programs {
		// programs的name 是 bcc的模块
		// 先检查配置文件的bcc模块有没有注册
		// * 注册的模块意味着conf存在相同的配置，不需要再加载
		// * 防止添加重复的bcc.module
		if _, ok := e.modules[program.Name]; ok {
			return fmt.Errorf("multiple programs with name %q", program.Name)
		}
		//* code返回是kaddr和code的string信息
		// * 解析program 变量/函数的kernel符号内存地址
		code, err := e.code(program)
		if err != nil {
			return err
		}
		//* NewModule会异步编译BPF code文件，生成一个BPF模块返回
		module := bcc.NewModule(code, program.Cflags)
		if module == nil {
			return fmt.Errorf("error compiling module for program %q", program.Name)
		}
		//* 向Kprobes、tracepoint和rawtracepoint添加编译后模块的函数
		//* tags是ebpf项目注入后得到的map[string]uint64
		//* 该语句意味着将探针后的产物tag全部加入tags
		tags, err := attach(module, program.Kprobes, program.Kretprobes, program.Tracepoints, program.RawTracepoints)

		if err != nil {
			return fmt.Errorf("failed to attach to program %q: %s", program.Name, err)
		}

		e.programTags[program.Name] = tags
		// * 若有perf_evnet事件，会在最后处理
		// * bcc.Modules.LoadPerfevent将导入BPF_PROG_TYPE_PERF_EVENT的程序
		for _, perfEventConfig := range program.PerfEvents {
			//target是一个文件描述符
			target, err := module.LoadPerfEvent(perfEventConfig.Target)
			if err != nil {
				return fmt.Errorf("failed to load target %q in program %q: %s", perfEventConfig.Target, program.Name, err)
			}
			// * 将性能事件fd——target加入perfEventConfig.Name头部的include/uapi/linux/perf_event
			err = module.AttachPerfEvent(perfEventConfig.Type, perfEventConfig.Name, perfEventConfig.SamplePeriod, perfEventConfig.SampleFrequency, -1, -1, -1, target)
			if err != nil {
				return fmt.Errorf("failed to attach perf event %d:%d to %q in program %q: %s", perfEventConfig.Type, perfEventConfig.Name, perfEventConfig.Target, program.Name, err)
			}
		}

		e.modules[program.Name] = module
	}

	return nil
}

// code generates program code, augmented if necessary
func (e Exporter) code(program config.Program) (string, error) {
	// * preamble
	preamble := ""
	/*
	 * programe.Kaddr是函数/变量名，如bpf_jit_current
	 * ebpf.Kaddr是map[string]uint64, key值是函数名，value值是函数存储的16位内存地址
	 */
	if len(program.Kaddrs) > 0 && len(e.kaddrs) == 0 {
		if err := e.populateKaddrs(); err != nil {
			return "", err
		}
	}

	defines := make([]string, 0, len(program.Kaddrs))
	for _, kaddr := range program.Kaddrs {
		// * defines会在所有的采集函数和变量中找到关键的programe.Kaddrs变量
		// ! 但带来的问题是 代价太大
		defines = append(defines, fmt.Sprintf("#define kaddr_%s 0x%x", kaddr, e.kaddrs[kaddr]))
	}

	preamble = preamble + strings.Join(defines, "\n")

	if preamble == "" {
		return program.Code, nil
	}

	return preamble + "\n\n" + program.Code, nil
}

// populateKaddrs populates cache of ksym -> kaddr mappings
// TODO: move to github.com/iovisor/gobpf/pkg/ksym
func (e Exporter) populateKaddrs() error {
	// * kallsyms - Extract all kernel symbols for debugging
	// * /proc/kallsyms包含了内核变量和函数的内存地址
	fd, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}

	defer fd.Close()
	// * read from fd
	s := bufio.NewScanner(fd)
	// * 读的过程
	for s.Scan() {
		parts := strings.Split(s.Text(), " ")
		if len(parts) != 3 {
			continue
		}
		// 对parts[0]的数值是16进制uint64类型转换存储的
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			return fmt.Errorf("error parsing addr %q from line %q: %s", parts[0], s.Text(), err)
		}
		// * /proc/kallsyms的第一个是解析地址，地址是以16进制存储的
		// * parts[2]的string是唯一标识符 变量名或函数名
		e.kaddrs[parts[2]] = addr
	}

	return s.Err()
}

// Describe satisfies prometheus.Collector interface by sending descriptions
// for all metrics the exporter can possibly report
// *实现采集器的describe接口
// *将全部的collector的描述符暴露给prometheus
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	// * addDescs的函数功能是为exporter的descs(暴露Metrics的描述符)添加。
	// * 这里拿ebpf_exporter范例举例
	// * e.desc[programName][name]——programName是programes:-name，name是metrics/histograms:-name
	// * prometheus.NewDesc(prometheus.BuildFQName(prometheusNamespace, "", name), help, labelNames, nil)
	// * 是“ebpf_exporter”+" "+"metrics:/histograms:/-name"+“labels:/-name”
	addDescs := func(programName string, name string, help string, labels []config.Label) {
		//
		if _, ok := e.descs[programName][name]; !ok {
			labelNames := []string{}

			for _, label := range labels {
				labelNames = append(labelNames, label.Name)
			}
			//*能找到的特征点全收集
			e.descs[programName][name] = prometheus.NewDesc(prometheus.BuildFQName(prometheusNamespace, "", name), help, labelNames, nil)
		}

		ch <- e.descs[programName][name]
	}
	//* Desc信息描述
	ch <- e.enabledProgramsDesc
	ch <- e.programInfoDesc
	//* Desc
	for _, program := range e.config.Programs {
		if _, ok := e.descs[program.Name]; !ok {
			//* 初始化，使得每一个program.Name可以对应一个Map
			//* 每一个指标的labelname对应一个*prometheus.Desc
			e.descs[program.Name] = map[string]*prometheus.Desc{}
		}
		//* 这里只定义了两个指标
		// * perf map事件
		for _, counter := range program.Metrics.Counters {
			if len(counter.PerfMap) != 0 {
				perfSink := NewPerfMapSink(e.decoders, e.modules[program.Name], counter)
				e.perfMapCollectors = append(e.perfMapCollectors, perfSink)
			}

			addDescs(program.Name, counter.Name, counter.Help, counter.Labels)
		}

		for _, histogram := range program.Metrics.Histograms {
			addDescs(program.Name, histogram.Name, histogram.Help, histogram.Labels[0:len(histogram.Labels)-1])
		}
	}
}

// Collect satisfies prometheus.Collector interface and sends all metrics
//*实现采集器Collect接口，真正的采集动作
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	//* 采集常量指标
	//* 前两个for是config配置信息
	for _, program := range e.config.Programs {

		ch <- prometheus.MustNewConstMetric(e.enabledProgramsDesc, prometheus.GaugeValue, 1, program.Name)
	}

	for program, tags := range e.programTags {
		for function, tag := range tags {
			ch <- prometheus.MustNewConstMetric(e.programInfoDesc, prometheus.GaugeValue, 1, program, function, fmt.Sprintf("%x", tag))
		}
	}
	//* 采集perf Map事件
	for _, perfMapCollector := range e.perfMapCollectors {
		perfMapCollector.Collect(ch)
	}

	e.collectCounters(ch)
	e.collectHistograms(ch)
}

// collectCounters sends all known counters to prometheus
func (e *Exporter) collectCounters(ch chan<- prometheus.Metric) {
	for _, program := range e.config.Programs {
		for _, counter := range program.Metrics.Counters {
			//* 有perfMap事件启动，那么不走collectCounters，因为已经走了
			//* perfMapCollector.Collect(ch)

			//! 有perfMap声明,不走collectCounters，真的适合项目吗？
			if len(counter.PerfMap) != 0 {
				continue
			}

			tableValues, err := e.tableValues(e.modules[program.Name], counter.Table, counter.Labels)
			if err != nil {
				log.Printf("Error getting table %q values for metric %q of program %q: %s", counter.Table, counter.Name, program.Name, err)
				continue
			}

			desc := e.descs[program.Name][counter.Name]

			for _, metricValue := range tableValues {
				ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, metricValue.value, metricValue.labels...)
			}
		}
	}
}

// collectHistograms sends all known historams to prometheus
func (e *Exporter) collectHistograms(ch chan<- prometheus.Metric) {
	for _, program := range e.config.Programs {
		for _, histogram := range program.Metrics.Histograms {
			skip := false

			histograms := map[string]histogramWithLabels{}

			tableValues, err := e.tableValues(e.modules[program.Name], histogram.Table, histogram.Labels)
			if err != nil {
				log.Printf("Error getting table %q values for metric %q of program %q: %s", histogram.Table, histogram.Name, program.Name, err)
				continue
			}

			// Taking the last label and using int as bucket delimiter, for example:
			//
			// Before:
			// * [sda, read, 1ms] -> 10
			// * [sda, read, 2ms] -> 2
			// * [sda, read, 4ms] -> 5
			//
			// After:
			// * [sda, read] -> {1ms -> 10, 2ms -> 2, 4ms -> 5}
			for _, metricValue := range tableValues {
				//* metricValue是从bcc table中取出的数据
				labels := metricValue.labels[0 : len(metricValue.labels)-1]

				key := fmt.Sprintf("%#v", labels)

				if _, ok := histograms[key]; !ok {
					histograms[key] = histogramWithLabels{
						labels:  labels,
						buckets: map[float64]uint64{},
					}
				}

				leUint, err := strconv.ParseUint(metricValue.labels[len(metricValue.labels)-1], 0, 64)
				if err != nil {
					log.Printf("Error parsing float value for bucket %#v in table %q of program %q: %s", metricValue.labels, histogram.Table, program.Name, err)
					skip = true
					break
				}

				histograms[key].buckets[float64(leUint)] = uint64(metricValue.value)
			}

			if skip {
				continue
			}

			desc := e.descs[program.Name][histogram.Name]

			for _, histogramSet := range histograms {
				buckets, count, sum, err := transformHistogram(histogramSet.buckets, histogram)
				if err != nil {
					log.Printf("Error transforming histogram for metric %q in program %q: %s", histogram.Name, program.Name, err)
					continue
				}

				// Sum is explicitly set to zero. We only take bucket values from
				// eBPF tables, which means we lose precision and cannot calculate
				// average values from histograms anyway.
				// Lack of sum also means we cannot have +Inf bucket, only some finite
				// value bucket, eBPF programs must cap bucket values to work with this.
				ch <- prometheus.MustNewConstHistogram(desc, count, sum, buckets, histogramSet.labels...)
			}
		}
	}
}

// tableValues returns values in the requested table to be used in metircs
func (e *Exporter) tableValues(module *bcc.Module, tableName string, labels []config.Label) ([]metricValue, error) {
	values := []metricValue{}
	//* New tables returns a refernce to a BPF table.
	//* 返回一个的bpf table结构。counter.Table用于ID排序
	//* &Table{
	//*	id:     id,
	//*	module: module,
	//* }
	table := bcc.NewTable(module.TableId(tableName), module)
	iter := table.Iter()

	for iter.Next() {
		key := iter.Key()
		raw, err := table.KeyBytesToStr(key)
		if err != nil {
			return nil, fmt.Errorf("error decoding key %v", key)
		}
		//* metricValue
		mv := metricValue{
			//* raw is what after transforming key
			raw: raw,
			//* labels is DecodeLabels(key,labels)
			//* labels是将raw再进一步的解码后的字符串组成的map
			labels: make([]string, len(labels)),
		}
		//* 对应labelname的labelvalue值
		mv.labels, err = e.decoders.DecodeLabels(key, labels)
		if err != nil {
			if err == decoder.ErrSkipLabelSet {
				continue
			}

			return nil, err
		}
		//* value值
		mv.value = float64(bcc.GetHostByteOrder().Uint64(iter.Leaf()))

		values = append(values, mv)
	}

	return values, nil
}

// *
func (e Exporter) exportTables() (map[string]map[string][]metricValue, error) {
	tables := map[string]map[string][]metricValue{}

	for _, program := range e.config.Programs {
		module := e.modules[program.Name]
		if module == nil {
			return nil, fmt.Errorf("module for program %q is not attached", program.Name)
		}

		if _, ok := tables[program.Name]; !ok {
			tables[program.Name] = map[string][]metricValue{}
		}

		metricTables := map[string][]config.Label{}

		for _, counter := range program.Metrics.Counters {
			if counter.Table != "" {
				metricTables[counter.Table] = counter.Labels
			}
		}

		for _, histogram := range program.Metrics.Histograms {
			if histogram.Table != "" {
				metricTables[histogram.Table] = histogram.Labels
			}
		}

		for name, labels := range metricTables {
			metricValues, err := e.tableValues(e.modules[program.Name], name, labels)
			if err != nil {
				return nil, fmt.Errorf("error getting values for table %q of program %q: %s", name, program.Name, err)
			}

			tables[program.Name][name] = metricValues
		}
	}

	return tables, nil
}

// TablesHandler is a debug handler to print raw values of kernel maps
func (e *Exporter) TablesHandler(w http.ResponseWriter, r *http.Request) {
	tables, err := e.exportTables()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("Content-type", "text/plain")
		if _, err = fmt.Fprintf(w, "%s\n", err); err != nil {
			log.Printf("Error returning error to client %q: %s", r.RemoteAddr, err)
			return
		}
		return
	}

	w.Header().Add("Content-type", "text/plain")

	buf := []byte{}

	for program, tables := range tables {
		buf = append(buf, fmt.Sprintf("## Program: %s\n\n", program)...)

		for name, table := range tables {
			buf = append(buf, fmt.Sprintf("### Table: %s\n\n", name)...)

			buf = append(buf, "```\n"...)
			for _, row := range table {
				buf = append(buf, fmt.Sprintf("%s (%v) -> %f\n", row.raw, row.labels, row.value)...)
			}
			buf = append(buf, "```\n\n"...)
		}
	}

	if _, err = w.Write(buf); err != nil {
		log.Printf("Error returning table contents to client %q: %s", r.RemoteAddr, err)
	}
}

// metricValue is a row in a kernel map
type metricValue struct {
	// raw is a raw key value provided by kernel
	raw string
	// labels are decoded from the raw key
	labels []string
	// value is the kernel map value
	value float64
}
