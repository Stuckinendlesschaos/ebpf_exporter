package main

import (
	"log"
	"net/http"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/cloudflare/ebpf_exporter/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"
)

func main() {
	// * 解析命令行参数
	configFile := kingpin.Flag("config.file", "Config file path").File()
	debug := kingpin.Flag("debug", "Enable debug").Bool()
	listenAddress := kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests").Default(":9435").String()
	metricsPath := kingpin.Flag("web.telemetry-path", "Path under which to expose metrics").Default("/metrics").String()
	kingpin.Version(version.Print("ebpf_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	//+++++++++++++++++++config解析yaml文件，进入Config结构++++++++++++++++++++++++++++++++//
	config := config.Config{}
	// * config 是一个Programe数组， *configFile是文件地址（一个yaml文件）
	// * 一个yaml对应一个Program结构
	// * 一个yaml文件将被解析成config的一个program元素
	err := yaml.NewDecoder(*configFile).Decode(&config)
	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}
	//++++++++++++++++++export实例化和将code等运行结果采集++++++++++++++++++++++++++++++++++++//
	// * 依赖config创建一个exporter实例
	// * 该exporter实例中仅包含config文件，和一个exporter必备的结构
	// * 这条语句仅是初始化
	e, err := exporter.New(config)
	if err != nil {
		log.Fatalf("Error creating exporter: %s", err)
	}
	// *导入code、kaddr的信息
	// *再导入探针的程序（再目标中导入程序）
	// *再导入perfevent性能事件
	// *导入的过程中，完善了exporter的两个信息：1.e.modules 2. e.programTags
	// * e.modules是ebpf模块（bcc编译后的）
	// * e.programeTags是kprobes等静动态追踪探针的结果
	err = e.Attach()
	if err != nil {
		log.Fatalf("Error attaching exporter: %s", err)
	}

	log.Printf("Starting with %d programs found in the config", len(config.Programs))
	//+++++++++++++++++普罗米修斯注册（包含度量收集）的收集器+++++++++++++++++++++++++//
	// * prometheus注册版本采集器——namespace:ebpf_exporter
	// * version.NewCollector是导出指标的集合（collector）
	err = prometheus.Register(version.NewCollector("ebpf_exporter"))
	if err != nil {
		log.Fatalf("Error registering version collector: %s", err)
	}
	// Register registers a new Collector to be included in metrics
	// collection.
	// * prometheus注册exporter(提供Collector)
	err = prometheus.Register(e)
	if err != nil {
		log.Fatalf("Error registering exporter: %s", err)
	}
	//+++++++++++++++++导出到HTTP页面+++++++++++++++++++++++++++++//
	// promhttp.Handler() returns an http.Handler for the prometheus.DefaultGatherer
	// * Handle处理 将promhttp.Handler()和*metricsPath的patterns("/metrics")绑定
	http.Handle(*metricsPath, promhttp.Handler())
	// * handleFunc将传入这种patten "/"的用这种剧名函数句柄去处理
	// * handle表示处理某种时间的函数（或者功能）
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err = w.Write([]byte(`<html>
			<head><title>eBPF Exporter</title></head>
			<body>
			<h1>eBPF Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
		if err != nil {
			log.Fatalf("Error sending response body: %s", err)
		}
	})
	//* 开启debug选项时的路径和事件处理
	if *debug {
		log.Printf("Debug enabled, exporting raw tables on /tables")
		http.HandleFunc("/tables", e.TablesHandler)
	}

	log.Printf("Listening on %s", *listenAddress)
	// * 一切准备就绪，那么开始监听。等待数据完成后显示到http上
	err = http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		log.Fatalf("Error listening on %s: %s", *listenAddress, err)
	}
}
