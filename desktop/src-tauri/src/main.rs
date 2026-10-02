// Windows 上 debug/release 都隐藏控制台（debug 构建双击启动不再弹黑框）；
// 排查需要 app 自身 stdout 时临时去掉本属性重编译。unix 不受影响。
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    desktop_lib::run()
}
