// File: rputn-srv.go
//
// Copyright (c) 2013 Charles Perkins
// 
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

package main

import (
]	"fmt"
	"net/url"
	"runtime"
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

        "rputbl.com/hashbase"
)

var hostname []byte
var hb HBstats

func pwdfile(f string) string {
	out := "File Read Error"
	content, err := ioutil.ReadFile(f)
	if err == nil {
		out = string(content)
	}
	return out
}

func reply2request(req string) string {

	return req
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s GET-HTML", hostname)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "%s", pwdfile("rputbl.html"))
}

func isAmpersand(r rune) bool {
	if r == '&' {
		return true
	}
	return false
}

func isSpace(r rune) bool {
	if r == ' ' {
		return true
	}
	return false
}

func assertHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if len(r.URL.String()) < 4 {
		cmc <- CM{i: CAssertBad, n: 1}
		fmt.Fprintf(w, "%s", "{\"error\" : \"malformed query (too small)\"}")
		log.Printf("%s BADASSERT-QUERY-FORMAT %s ", hostname, r.URL.String())
		return
	}

	qline := r.URL.String()[3:]

	qFields := strings.FieldsFunc(qline, isAmpersand)

	if len(qFields) < 4 {
		cmc <- CM{i: CAssertBad, n: 1}
		fmt.Fprintf(w, "%s", "{\"error\" : \"malformed query (too few fields)\"}")
		log.Printf("%s BADASSERT-QUERY-FORMAT %s ", hostname, r.URL.String())
		return
	}

	fh64val := qFields[0]
	fhbv, err := hashbase.Un64(fh64val)
	if err != nil {
		cmc <- CM{i: CAssertBad, n: 1}
		fmt.Fprintf(w, "%s", "{\"error\" : \"malformed file hash\"}")
		log.Printf("%s BADASSERT-BASE64-DECODE %s ", hostname, qline)
		return
	}
	if len(fhbv) != 28 {
		cmc <- CM{i: CAssertBad, n: 1}
		fmt.Fprintf(w, "%s", "{\"error\" : \"this is not a SHA224 (28 byte) file hash\"}")
		log.Printf("%s BADASSERT-SHA224-SIZE %s ", hostname, qline)
		return
	}

	ph64val := qFields[1]
	phbv, err := hashbase.Un64(ph64val)
	if err != nil {
		cmc <- CM{i: CAssertBad, n: 1}
		fmt.Fprintf(w, "%s", "{\"error\" : \"malformed asserter hash\"}")
		log.Printf("%s BADASSERT-BASE64-DECODE %s ", hostname, qline)
		return
	}
	if len(phbv) != 28 {
		cmc <- CM{i: CAssertBad, n: 1}
		fmt.Fprintf(w, "%s", "{\"error\" : \"this is not a SHA224 (28 byte) asserter hash\"}")
		log.Printf("%s BADASSERT-SHA224-SIZE %s ", hostname, qline)
		return
	}

	assertstr := qFields[2]
	if len(assertstr) < 1 {
		cmc <- CM{i: CAssertBad, n: 1}
		fmt.Fprintf(w, "%s", "{\"error\" : \"malformed assert content\"}")
		log.Printf("%s BADASSERT-ASSERT-FORMAT %s ", hostname, qline)
		return
	}

	sigstr := qFields[3]
	if len(sigstr) < 1 {
		cmc <- CM{i: CAssertBad, n: 1}
		fmt.Fprintf(w, "%s", "{\"error\" : \"malformed signature content\"}")
		log.Printf("%s BADASSERT-SIGNATURE-FORMAT %s ", hostname, qline)
		return
	}
	cmc <- CM{i: CAssertGood, n: 1}

	_, exists := i[ph64val]
	if !exists {
		fmt.Fprintf(w, "%s", "{\"error\" : \"unknown asserter\"}")
		log.Printf("%s DENIEDASSERT-UNKNOWN-ASSERTER %s ", hostname, qline)
		return
	}

	cmc <- CM{i: CAssertion, n: 1}
	fmt.Fprintf(w, "%s", "{\"ok\" : \"query understood\"}")

	m[fh64val] = assertstr
	log.Printf("%s ASSERT %s by %s is %s", hostname, fh64val, ph64val, assertstr)

}

func queryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	hash64val := r.URL.String()[3:]
	hbv, err := hashbase.Un64(hash64val)
	if err != nil {
		cmc <- CM{i: CQueryBad, n: 1}
		fmt.Fprintf(w, "%s", "{\"error\" : \"malformed base64 encoding\"}")
		log.Printf("%s BADQUERY-BASE64-DECODE %s ", hostname, r.URL.String()[3:])
	} else {
		if len(hbv) != 28 {
			cmc <- CM{i: CQueryBad, n: 1}
			fmt.Fprintf(w, "%s", "{\"error\" : \"this is not a SHA224 (28 byte) hash\"}")
			log.Printf("%s BADQUERY-SHA224-SIZE %s ", hostname, r.URL.String()[3:])
		} else {
			assert, exists := m[hash64val]
			if exists {
				cmc <- CM{i: CQueryGood, n: 1}
				fmt.Fprintf(w, "%s%s%s", "{\"ok\" : \"success\",\"asserted\" : \"", assert, "\"}")
				log.Printf("%s QUERY %s ", hostname, r.URL.String()[3:])
			} else {
				cmc <- CM{i: CQueryGood, n: 1}
				fmt.Fprintf(w, "%s", "{\"ok\" : \"no such hash\"}")
				log.Printf("%s QUERY %s ", hostname, r.URL.String()[3:])
			}
		}
	}

}

func introHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	//    log.Printf("DEBUG-YEEK")
	//    fmt.Fprintf(w, "%s", "{\"debug\" : \"YEEK\"}")

	if len(r.URL.String()) < 4 {
		//      cmc <- CM{ i: CAssertBad, n:1 }
		fmt.Fprintf(w, "%s", "{\"error\" : \"malformed query (too small)\"}")
		log.Printf("%s BADINTRO-QUERY-FORMAT %s ", hostname, r.URL.String())
		return
	}

	qline := r.URL.String()[3:]

	qFields := strings.FieldsFunc(qline, isAmpersand)

	if len(qFields) < 2 {
		//      cmc <- CM{ i: CAssertBad, n:1 }
		fmt.Fprintf(w, "%s", "{\"error\" : \"malformed query (too few fields)\"}")
		log.Printf("%s BADINTRO-QUERY-FORMAT %s ", hostname, r.URL.String())
		return
	}

	ph64val := qFields[0]
	phbv, err := hashbase.Un64(ph64val)
	if err != nil {
		//      cmc <- CM{ i: CAssertBad, n:1 }
		fmt.Fprintf(w, "%s", "{\"error\" : \"malformed file hash\"}")
		log.Printf("%s BADINTRO-BASE64-DECODE %s ", hostname, qline)
		return
	}
	if len(phbv) != 28 {
		//      cmc <- CM{ i: CAssertBad, n:1 }
		fmt.Fprintf(w, "%s", "{\"error\" : \"this is not a SHA224 (28 byte) public key hash\"}")
		log.Printf("%s BADINTRO-SHA224-SIZE %s ", hostname, qline)
		return
	}

	rsa_pub, err := url.QueryUnescape(qFields[1])
	if err != nil {
		//      cmc <- CM{ i: CAssertBad, n:1 }
		fmt.Fprintf(w, "%s", "{\"error\" : \"malformed escaped pubkey\"}")
		log.Printf("%s BADINTRO-PUBKEY-UNESCAPE %s ", hostname, qline)
		return
	}

	rsa_pub_stored, exists := i[ph64val]

	if exists {

		lspi := strings.LastIndex(rsa_pub_stored, " ")
		if lspi < 1 {
			//            cmc <- CM{ i: CAssertBad, n:1 }
			fmt.Fprintf(w, "%s", "{\"error\" : \"malformed stored user record\"}")
			log.Printf("%s BADINTRO-STOREDKEY-DECODE %s ", hostname, qline)
			return
		}

		rsa_pub_name := strings.Trim(rsa_pub_stored[lspi+1:], " \n")

		fmt.Fprintf(w, "%s%s%s", "{\"ok\" : \"success\",\"remembered\" : \"", rsa_pub_name, "\"}")
		log.Printf("%s INTRO-ALREADY %s ", hostname, rsa_pub_name)
	} else {
		lspi := strings.LastIndex(rsa_pub, " ")
		if lspi < 1 {
			//            cmc <- CM{ i: CAssertBad, n:1 }
			fmt.Fprintf(w, "%s", "{\"error\" : \"malformed stored user record\"}")
			log.Printf("%s BADINTRO-STOREDKEY-DECODE %s ", hostname, qline)
			return
		}

		rsa_pub_name := strings.Trim(rsa_pub[lspi+1:], " \n")

		cmc <- CM{i: CIntroduction, n: 1}
		i[ph64val] = rsa_pub

		fmt.Fprintf(w, "%s%s%s", "{\"ok\" : \"success\",\"introduced\" : \"", rsa_pub_name, "\"}")
		log.Printf("%s INTRO-NEW %s ", hostname, rsa_pub_name)
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
	if 1 == 1 {
		log.Printf("AUTH-SUCCESS")
		fmt.Fprintf(w, "%s", "{\"success\" : \"login is successful\", \"userid\" : \"33\"}")
	} else {
		fmt.Fprintf(w, "%s", "{{\"error\" : \"username or password is wrong\"}}")
	}
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "THIS IS FROM AJAX")
	//		ctx.Request.ParseForm()
	//		data := ctx.Request.FormValue("data")
	//		return reply2request(data)
}

type HBstats struct {
	Hostname    [32]byte
	Pid         int
	Assertions  uint32
	Identities  uint32
	Hashcap     uint32
	Hashload    uint32
	Disksize    uint32
	Diskuse     uint32
	Repclan     uint32
	Shardspan   uint32
	Connections uint32
	Qgsec       [60]int
	Agsec       [60]int
	Qbsec       [60]int
	Absec       [60]int
	Respms      [60]int
	Cpuload     string
	Memuse      uint32
	Netuse      uint32
}

func Acc60(itm [60]int) int {

	var acc int
	acc = 0
	for i := 0; i < 60; i++ {
		acc = acc + itm[i]
	}
	return acc
}

func statusHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	fmt.Fprintf(w, "{")
	fmt.Fprintf(w, "\"hostname\" : \"%s\",", hostname)
	fmt.Fprintf(w, "\"pid\" : \"%d\",", hb.Pid)
	fmt.Fprintf(w, "\"assertions\" : \"%d\",", hb.Assertions)
	fmt.Fprintf(w, "\"identities\" : \"%d\",", hb.Identities)
	fmt.Fprintf(w, "\"hashcap\" : \"%d\",", hb.Hashcap)
	fmt.Fprintf(w, "\"hashload\" : \"%d\",", hb.Hashload)
	fmt.Fprintf(w, "\"disksize\" : \"%d\",", hb.Disksize)
	fmt.Fprintf(w, "\"diskuse\" : \"%d\",", hb.Diskuse)
	fmt.Fprintf(w, "\"repclan\" : \"%d\",", hb.Repclan)
	fmt.Fprintf(w, "\"shardspan\" : \"%d\",", hb.Shardspan)
	fmt.Fprintf(w, "\"connections\" : \"%d\",", hb.Connections)
	fmt.Fprintf(w, "\"qgsec\" : \"%d\",", Acc60(hb.Qgsec))
	fmt.Fprintf(w, "\"agsec\" : \"%d\",", Acc60(hb.Agsec))
	fmt.Fprintf(w, "\"qbsec\" : \"%d\",", Acc60(hb.Qbsec))
	fmt.Fprintf(w, "\"absec\" : \"%d\",", Acc60(hb.Absec))
	fmt.Fprintf(w, "\"respms\" : \"%d\",", Acc60(hb.Respms))
	fmt.Fprintf(w, "\"cpuload\" : \"%s\",", hb.Cpuload)
	fmt.Fprintf(w, "\"memuse\" : \"%d\",", hb.Memuse)
	fmt.Fprintf(w, "\"netuse\" : \"%d\"", hb.Netuse)
	fmt.Fprintf(w, "}")

}

func getHostname() {

	cmd := exec.Command("hostname")
	bs, err := cmd.Output()
	if err != nil {
	}
	offset := bytes.IndexRune(bs, '.')
	if offset < 1 {
		offset = len(bs)
	}
	hostname = bs[:offset]
	offset = bytes.IndexRune(hostname, '\n')
	if offset < 1 {
		offset = len(hostname)
	}
	hostname = hostname[:offset]

}

func getLoad() string {

	switch runtime.GOOS {
	case "windows": // ...
		return "Windows"
	case "linux": // ...
		cmd := exec.Command("cat", "/proc/loadavg")
		bs, err := cmd.Output()
		if err != nil {
			return "top error"
		}
		offset := bytes.IndexRune(bs, '\n')
		if offset < 1 {
			offset = len(bs)
		}
		return string(bs[:offset])
	case "freebsd": // ...
		return "freebsd"
	case "darwin": // ...
		cmd := exec.Command("sysctl", "-n", "vm.loadavg")
		bs, err := cmd.Output()
		if err != nil {
			return "top error"
		}
		offset := bytes.IndexRune(bs, '\n')
		if offset < 1 {
			offset = len(bs)
		}
		return string(bs[:offset])
	}
	return "dunno!"

}

func listenForClientsSSL() {
	log.Printf("Listening for clients on 8081/SSL")
	err := http.ListenAndServeTLS(":8081", "cert.pem", "key.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
}
func listenForClientsHTTP() {
	log.Printf("Listening for clients on 8082/HTTP")
	err := http.ListenAndServe(":8082", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func housekeeping() {
	for {
		hb.Cpuload = getLoad()
		time.Sleep(1 * time.Second)
	}
}

type CM struct {
	i int
	n int
}

var cmc chan CM

var qgc chan int
var agc chan int
var qbc chan int
var abc chan int
var rmc chan int

const (
	CAssertion = iota
	CIntroduction
	CQueryGood
	CQueryBad
	CAssertGood
	CAssertBad
	CResponseMs
)

func cmrecord() {
	var cm CM
	for {
		cm = <-cmc
		switch cm.i {
		case CAssertion:
			hb.Assertions = hb.Assertions + uint32(cm.n)
		case CIntroduction:
			hb.Identities = hb.Identities + uint32(cm.n)
		case CQueryGood:
			hb.Qgsec[0] = hb.Qgsec[0] + cm.n
		case CQueryBad:
			hb.Qbsec[0] = hb.Qbsec[0] + cm.n
		case CAssertGood:
			hb.Agsec[0] = hb.Agsec[0] + cm.n
		case CAssertBad:
			hb.Absec[0] = hb.Absec[0] + cm.n
		case CResponseMs:
			hb.Respms[0] = hb.Respms[0] + cm.n
		}
	}
}

var m map[string]string
var i map[string]string

func main() {

	m = make(map[string]string)
	i = make(map[string]string)

	getHostname()
	go housekeeping()

	hb.Pid = os.Getpid()
	hb.Assertions = 0
	hb.Identities = 0
	hb.Hashcap = 0
	hb.Hashload = 0
	hb.Disksize = 0
	hb.Diskuse = 0
	hb.Repclan = 0
	hb.Shardspan = 0
	hb.Connections = 0

	hb.Memuse = 0
	hb.Netuse = 0

	cmc = make(chan CM)

	go cmrecord()

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
