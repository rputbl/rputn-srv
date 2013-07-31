package main


import (
    "runtime"
    "fmt"
    "encoding/base64"
//    "encoding/hex"
    "bytes"
    "strings"
    "os/exec"
    "os"
    "net/http"
    "io/ioutil"
    "log"
    "time"
)


var hostname []byte
var hb	HBstats

func pwdfile(f string) string {
	out := "File Read Error"
	content, err := ioutil.ReadFile(f)
	if err == nil {
		out = string(content)
	}
	return out
}





func reply2request(req string) string{

  return req
}







func rootHandler(w http.ResponseWriter, r *http.Request) {
    log.Printf("%s GET-HTML",hostname)
    w.Header().Set("Content-Type", "text/html")
    fmt.Fprintf(w, "%s", pwdfile("rputbl.html"))
}

func assertHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    sep:=strings.IndexRune(r.URL.String(),'&')
    if sep < 28 {
      abc <- 1
      fmt.Fprintf(w, "%s", "{\"error\" : \"malformed base64 encoding\"}")
      log.Printf("%s BADASSERT-ASSERT-PARSE %s ",hostname, r.URL.String()[3:])
    }else{
      hash64val := r.URL.String()[3:sep]
      afterhash := r.URL.String()[sep+1:]
      sep2:=strings.IndexRune(afterhash,'&')

      if sep2 < 1 {
        abc <- 1
        fmt.Fprintf(w, "%s", "{\"error\" : \"missing assert or signature\"}")
        log.Printf("%s BADASSERT-ASSERT-AORSIG %s ",hostname, r.URL.String()[3:])
      }else{

        hbv, err := base64.StdEncoding.DecodeString(hash64val)
        if err != nil {
          abc <- 1
          fmt.Fprintf(w, "%s", "{\"error\" : \"malformed base64 encoding\"}")
          log.Printf("%s BADASSERT-BASE64-DECODE %s ",hostname, r.URL.String()[3:])
        }else{
          if len(hbv)!=28{
            abc <- 1
            fmt.Fprintf(w, "%s", "{\"error\" : \"this is not a SHA224 (28 byte) hash\"}")
            log.Printf("%s BADASSERT-SHA224-SIZE %s ",hostname, r.URL.String()[3:])
          }else{

            agc <- 1
            fmt.Fprintf(w, "%s", "{\"ok\" : \"query understood\"}")
	    m[hash64val]=afterhash[:sep2]
            log.Printf("%s ASSERT %s %s",hostname, hash64val, afterhash[:sep2])
          }
        }
      }
    }
}

func queryHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    hash64val := r.URL.String()[3:]
    hbv, err := base64.StdEncoding.DecodeString(hash64val)
    if err != nil {
      qbc <- 1
      fmt.Fprintf(w, "%s", "{\"error\" : \"malformed base64 encoding\"}")
      log.Printf("%s BADQUERY-BASE64-DECODE %s ",hostname, r.URL.String()[3:])
    }else{
      if len(hbv)!=28{
        qbc <- 1
        fmt.Fprintf(w, "%s", "{\"error\" : \"this is not a SHA224 (28 byte) hash\"}")
        log.Printf("%s BADQUERY-SHA224-SIZE %s ",hostname, r.URL.String()[3:])
      }else{
	assert,exists:=m[hash64val]
	if exists {
          qgc <- 1
          fmt.Fprintf(w, "%s%s%s", "{\"ok\" : \"success\",\"asserted\" : \"",assert,"\"}")
          log.Printf("%s QUERY %s ",hostname, r.URL.String()[3:])
	}else{
          qgc <- 1
          fmt.Fprintf(w, "%s", "{\"ok\" : \"no such hash\"}")
          log.Printf("%s QUERY %s ",hostname, r.URL.String()[3:])
	}
      }
    }

    

}

func introHandler(w http.ResponseWriter, r *http.Request) {
    qbc <- 1
    w.Header().Set("Content-Type", "application/json")
    hash64val := r.URL.String()[3:]
    hbv, err := base64.StdEncoding.DecodeString(hash64val)
    if err != nil {
      fmt.Fprintf(w, "%s", "{\"error\" : \"malformed base64 encoding\"}")
      log.Printf("%s BADQUERY-BASE64-DECODE %s ",hostname, r.URL.String()[3:])
    }else{
      if len(hbv)!=28{
        fmt.Fprintf(w, "%s", "{\"error\" : \"this is not a SHA224 (28 byte) hash\"}")
        log.Printf("%s BADQUERY-SHA224-SIZE %s ",hostname, r.URL.String()[3:])
      }else{
	assert,exists:=m[hash64val]
	if exists {
          fmt.Fprintf(w, "%s%s%s", "{\"ok\" : \"success\",\"asserted\" : \"",assert,"\"}")
          log.Printf("%s QUERY %s ",hostname, r.URL.String()[3:])
	}else{
          fmt.Fprintf(w, "%s", "{\"ok\" : \"no such hash\"}")
          log.Printf("%s QUERY %s ",hostname, r.URL.String()[3:])
	}
      }
    }

    

}

func ieCssHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/css")
    fmt.Fprintf(w, "%s", pwdfile("ie.css"))
}

func printCssHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/css")
    fmt.Fprintf(w, "%s", pwdfile("print.css"))
}

func screenCssHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/css")
    fmt.Fprintf(w, "%s", pwdfile("screen.css"))
}

func buttonScreenCssHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    fmt.Fprintf(w, "%s", pwdfile("button-screen.css"))
}

func loginJsHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    fmt.Fprintf(w, "%s", pwdfile("login.js"))
}

func jqueryJsHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    fmt.Fprintf(w, "%s", pwdfile("jquery-1.4.4.min.js"))
}

func tickPngHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    fmt.Fprintf(w, "%s", pwdfile("tick.png"))
}

func authenticateHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    if 1==1{
    log.Printf("AUTH-SUCCESS")
      fmt.Fprintf(w, "%s", "{\"success\" : \"login is successful\", \"userid\" : \"33\"}")
    }else{
      fmt.Fprintf(w, "%s", "{{\"error\" : \"username or password is wrong\"}}")
    }
}


func echoHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w,"THIS IS FROM AJAX")
//		ctx.Request.ParseForm()
//		data := ctx.Request.FormValue("data")
//		return reply2request(data)
}


type HBstats struct {
	
	Hostname [32]byte
	Pid int
	Assertions uint32
	Hashcap uint32
	Hashload uint32
	Disksize uint32
	Diskuse uint32
	Repclan uint32
	Shardspan uint32
	Connections uint32
	Qgsec [60]int
	Agsec [60]int
	Qbsec [60]int
	Absec [60]int
	Respms [60]int
	Cpuload string
	Memuse uint32
	Netuse uint32
}


func Acc60( itm [60]int) int{

	var acc int
	acc = 0
	for i:=0; i<60; i++{
		acc = acc + itm[i]
	}
	return acc 
}


func statusHandler(w http.ResponseWriter, r *http.Request) {

    w.Header().Set("Content-Type", "application/json")



	fmt.Fprintf(w,"{")
	fmt.Fprintf(w,"\"hostname\" : \"%s\",",hostname)
	fmt.Fprintf(w,"\"pid\" : \"%d\",",hb.Pid)
	fmt.Fprintf(w,"\"assertions\" : \"%d\",",hb.Assertions)
	fmt.Fprintf(w,"\"hashcap\" : \"%d\",",hb.Hashcap)
	fmt.Fprintf(w,"\"hashload\" : \"%d\",",hb.Hashload)
	fmt.Fprintf(w,"\"disksize\" : \"%d\",",hb.Disksize)
	fmt.Fprintf(w,"\"diskuse\" : \"%d\",",hb.Diskuse)
	fmt.Fprintf(w,"\"repclan\" : \"%d\",",hb.Repclan)
	fmt.Fprintf(w,"\"shardspan\" : \"%d\",",hb.Shardspan)
	fmt.Fprintf(w,"\"connections\" : \"%d\",",hb.Connections)
	fmt.Fprintf(w,"\"qgsec\" : \"%d\",",Acc60(hb.Qgsec))
	fmt.Fprintf(w,"\"agsec\" : \"%d\",",Acc60(hb.Agsec))
	fmt.Fprintf(w,"\"qbsec\" : \"%d\",",Acc60(hb.Qbsec))
	fmt.Fprintf(w,"\"absec\" : \"%d\",",Acc60(hb.Absec))
	fmt.Fprintf(w,"\"respms\" : \"%d\",",Acc60(hb.Respms))
	fmt.Fprintf(w,"\"cpuload\" : \"%s\",",hb.Cpuload)
	fmt.Fprintf(w,"\"memuse\" : \"%d\",",hb.Memuse)
	fmt.Fprintf(w,"\"netuse\" : \"%d\"",hb.Netuse)
	fmt.Fprintf(w,"}")

}

func getHostname() {

	cmd := exec.Command("hostname")
	bs, err := cmd.Output()
	if err != nil {  }
	offset := bytes.IndexRune(bs,'.')
	if offset < 1 { offset = len(bs) }
	hostname = bs[:offset]
	offset = bytes.IndexRune(hostname,'\n')
	if offset < 1 { offset = len(hostname) }
	hostname = hostname[:offset]


}



func getLoad()string {


	switch runtime.GOOS {
	case "windows": // ...
		return "Windows"
	case "linux": // ...
		cmd := exec.Command("cat", "/proc/loadavg")
		bs, err := cmd.Output()
		if err != nil { return "top error" }
		offset := bytes.IndexRune(bs,'\n')
		if offset < 1 { offset = len(bs) }
		return string(bs[:offset])
	case "freebsd": // ...
		return "freebsd"
	case "darwin": // ...
		cmd := exec.Command("sysctl", "-n", "vm.loadavg")
		bs, err := cmd.Output()
		if err != nil { return "top error" }
		offset := bytes.IndexRune(bs,'\n')
		if offset < 1 { offset = len(bs) }
		return string(bs[:offset])
	}
	return "dunno!"



}




func listenForClientsSSL(){
	log.Printf("Listening for clients on 8081/SSL")
	err := http.ListenAndServeTLS(":8081", "cert.pem", "key.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
}
func listenForClientsHTTP(){
	log.Printf("Listening for clients on 8082/HTTP")
	err := http.ListenAndServe(":8082", nil)
	if err != nil {
		log.Fatal(err)
	}
}


func housekeeping() {
    for ; ; {
	hb.Cpuload = getLoad()
        time.Sleep(1 * time.Second)
    }
}

var qgc chan int
var agc chan int
var qbc chan int
var abc chan int
var rmc chan int


func qgrcv(){
	var v int
	for ;; {
		v = <- qgc
		hb.Qgsec[0]=hb.Qgsec[0]+v
	}
}
func agrcv(){
	var v int
	for ;; {
		v = <- agc
		hb.Agsec[0]=hb.Agsec[0]+v
	}
}
func qbrcv(){
	var v int
	for ;; {
		v = <- qbc
		hb.Qbsec[0]=hb.Qbsec[0]+v
	}
}
func abrcv(){
	var v int
	for ;; {
		v = <- abc
		hb.Absec[0]=hb.Absec[0]+v
	}
}
func rmrcv(){
	var v int
	for ;; {
		v = <- rmc
		hb.Respms[0]=hb.Respms[0]+v
	}
}

var m map[string]string

func main() {

	m = make(map[string]string)
	
	getHostname()
	go housekeeping()

	hb.Pid = os.Getpid()
	hb.Assertions = 0
	hb.Hashcap = 0
	hb.Hashload = 0
	hb.Disksize = 0
	hb.Diskuse = 0
	hb.Repclan = 0
	hb.Shardspan = 0
	hb.Connections = 0

	hb.Memuse = 0
	hb.Netuse = 0

	qgc = make(chan int)
	agc = make(chan int)
	qbc = make(chan int)
	abc = make(chan int)
	rmc = make(chan int)

	go qgrcv()
	go agrcv()
	go qbrcv()
	go abrcv()
	go rmrcv()

	http.HandleFunc("/", rootHandler)

	http.HandleFunc("/a", assertHandler)

	http.HandleFunc("/q", queryHandler)

	http.HandleFunc("/i", introHandler)

	http.HandleFunc("/ie.css", ieCssHandler)
	http.HandleFunc("/print.css", printCssHandler)
	http.HandleFunc("/screen.css", screenCssHandler)
	http.HandleFunc("/buttons-screen.css", buttonScreenCssHandler)
	http.HandleFunc("/login.js", loginJsHandler)
	http.HandleFunc("/jquery-1.4.4.min.js", jqueryJsHandler)
	http.HandleFunc("/tick.png", tickPngHandler)
	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/authenticate", authenticateHandler)

	http.HandleFunc("/ejax", echoHandler)

	go listenForClientsSSL()
	listenForClientsHTTP()
}

