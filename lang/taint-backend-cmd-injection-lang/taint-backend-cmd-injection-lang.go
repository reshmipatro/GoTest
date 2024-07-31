package main

// This test file is a bit of a hellscape.
// My sincerest apologies to whoever has to work on this next 🫶.

import (
	"net/http"
	"os"
	"os/exec"
	"syscall"
)

var whiteList map[string]struct{}

func init() {
	whiteList = make(map[string]struct{})
	whiteList["echo"] = struct{}{}
}

func programInjectionExec(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	// ruleid: taint-backend-cmd-injection-lang
	exec.Command(data)
}

func programInjectionOs(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	// ruleid: taint-backend-cmd-injection-lang
	os.StartProcess(data, make([]string, 0), nil)
}

func interpreterExecE(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	// ruleid: taint-backend-cmd-injection-lang
	exec.Command("ruby", "-e", data)
}

func GoodInterpreterExecE(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	// ok: taint-backend-cmd-injection-lang
	exec.Command("ruby", "-P", data)
}

func interpreterExecC(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	// ruleid: taint-backend-cmd-injection-lang
	exec.Command("ipython3", "-c", data)
}

func GoodinterpreterExecC(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	// ok: taint-backend-cmd-injection-lang
	exec.Command("ipython3", "--test", data)
}

func interpreterOsE(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	var args [4]string
	args[0] = "--verbose"
	args[1] = "-e"
	args[2] = data
	args[3] = "--jit"
	// todoruleid: taint-backend-cmd-injection-lang
	os.StartProcess("node", args[:], nil)
}

func GoodinterpreterOsE(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	var args [4]string
	args[0] = "--verbose"
	args[1] = "-e"
	args[2] = "--jit"
	args[3] = data
	// ok: taint-backend-cmd-injection-lang
	os.StartProcess("node", args[:], nil)
}

func interpreterOsC(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	var args [4]string
	args[0] = "--verbose"
	args[1] = "-c"
	args[2] = data
	args[3] = "--jit"
	// todoruleid: taint-backend-cmd-injection-lang
	os.StartProcess("zsh", args[:], nil)
}

func GoodinterpreterOsC(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	var args [4]string
	args[0] = "--verbose"
	args[1] = "-c"
	args[2] = "--jit"
	args[3] = data
	// ok: taint-backend-cmd-injection-lang
	os.StartProcess("zsh", args[:], nil)
}

func execCmdProg1(resp http.ResponseWriter, req *http.Request) {
	// ruleid: taint-backend-cmd-injection-lang
	_ = exec.Cmd{Path: req.FormValue("evil")}
}

func GoodexecCmdProg1(resp http.ResponseWriter, req *http.Request) {
	// ok: taint-backend-cmd-injection-lang
	_ = exec.Cmd{Path: "ls"}
}

func execCmdProg2(resp http.ResponseWriter, req *http.Request) {
	// This is disabled for now for performance reasons
	// todoruleid: taint-backend-cmd-injection-lang
	_ = exec.Cmd{Args: []string{req.FormValue("evil")}}
}

func GoodexecCmdProg2(resp http.ResponseWriter, req *http.Request) {
	// ok: taint-backend-cmd-injection-lang
	_ = exec.Cmd{Path: "ls", Args: []string{req.FormValue("evil")}}
}

func execCmdInterpreterInline1(resp http.ResponseWriter, req *http.Request) {
	// ruleid: taint-backend-cmd-injection-lang
	_ = exec.Cmd{Path: "zsh", Args: []string{"-c", req.FormValue("evil")}}
}

func GoodexecCmdInterpreterInline1(resp http.ResponseWriter, req *http.Request) {
	// ok: taint-backend-cmd-injection-lang
	_ = exec.Cmd{Path: "ls", Args: []string{"-c", req.FormValue("evil")}}
}

func execCmdInterpreterInline2(resp http.ResponseWriter, req *http.Request) {
	// ruleid: taint-backend-cmd-injection-lang
	_ = exec.Cmd{Args: []string{"zsh", "-c", req.FormValue("evil")}}
}

func GoodexecCmdInterpreterInline2(resp http.ResponseWriter, req *http.Request) {
	// ok: taint-backend-cmd-injection-lang
	_ = exec.Cmd{Args: []string{"zsh", "-s", req.FormValue("evil")}}
}

func interpreterOsCInline(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	// ruleid: taint-backend-cmd-injection-lang
	os.StartProcess("zsh", []string{"-c", data}, nil)
}

func GoodinterpreterOsCInline(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")
	// ok: taint-backend-cmd-injection-lang
	os.StartProcess("zsh", []string{"-f", data}, nil)
}

func interpreterSyscallCInline(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")

	// ruleid: taint-backend-cmd-injection-lang
	syscall.Exec("zsh", []string{"-c", data}, nil)
}

func GoodinterpreterSyscallCInline(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")

	// ok: taint-backend-cmd-injection-lang
	syscall.Exec("ls", []string{"-c", data}, nil)
}

func interpreterSyscallForkCInline(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")

	// ruleid: taint-backend-cmd-injection-lang
	syscall.ForkExec("zsh", []string{"-c", data}, nil)
}

func GoodinterpreterSyscallForkCInline(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")

	// ok: taint-backend-cmd-injection-lang
	syscall.ForkExec("ls", []string{"-c", data}, nil)
}

func TestAssignments(resp http.ResponseWriter, req *http.Request) {
	cmd := exec.Cmd{}
	cmdPointer := &exec.Cmd{}

	// This is disabled for now for performance reasons
	// todoruleid: taint-backend-cmd-injection-lang
	cmd.Path = req.FormValue("evil")
	// This is disabled for now for performance reasons
	// todoruleid: taint-backend-cmd-injection-lang
	cmdPointer.Path = req.FormValue("evil")

	noPath := exec.Cmd{}
	// This is disabled for now for performance reasons
	// todoruleid: taint-backend-cmd-injection-lang
	noPath.Args[0] = req.FormValue("evil")

	pathInConstructor := exec.Cmd{Path: "ls"}
	// ok: taint-backend-cmd-injection-lang
	pathInConstructor.Args[0] = req.FormValue("evil")

	pathAssign := exec.Cmd{}
	// ok: taint-backend-cmd-injection-lang
	pathAssign.Args[0] = req.FormValue("evil")
	pathAssign.Path = "ls"

	pathAssign2 := exec.Cmd{}
	pathAssign2.Path = "ls"
	// ok: taint-backend-cmd-injection-lang
	pathAssign2.Args[0] = req.FormValue("evil")

}

func sanitized(resp http.ResponseWriter, req *http.Request) {
	data := req.FormValue("evil")

	if _, ok := whiteList[data]; ok {
		// ok: taint-backend-cmd-injection-lang
		exec.Command(data, "test")
	}
}

func sanitizedExecCommand(resp http.ResponseWriter, req *http.Request) {
	req.ParseMultipartForm(1024)
	command, exists := req.MultipartForm.Value["cmd"]

	if !exists || len(command) == 0 {
		http.Error(resp, "Form value 'cmd' is required", 400)
		return
	}

	prog := command[0]
	args, exists := req.MultipartForm.Value["args"]

	if !exists {
		args = make([]string, 0)
	}

	if _, ok := whiteList[prog]; ok {
		// ok: taint-backend-cmd-injection-lang
		exec.Command(prog, args...)
	}
}
