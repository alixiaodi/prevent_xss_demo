window.setInterval(exec, 1000);
var xmlHttp = new XMLHttpRequest()

function exec() {
    xmlHttp.open("get", "http://127.0.0.1:8080/demo/xssTest?parameter=我是恶意攻击");
    xmlHttp.send()
    console.log("正在进行恶意攻击")
}