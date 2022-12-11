# Crash Monitor
Crash Monitor is a tool that acts as a debugger and monitors crashes in a program. If a monitored program crashes by receiving "Access Violation" exception program saves current program state by creating a crash dump. It also serves the current crash status on a sparate thread to integrate with a external fuzzer. See [boofuzz integration](#example-run-with-boofuzz).

## Building and Running
To build and run Crash Monitor, you will need the `nightly-i686-pc-windows-msvc` toolchain. You can install it using `rustup install nightly-i686-pc-windows-msvc`.

Once you have the toolchain installed, clone the repository and build the project using the following commands:

```
git clone https://github.com/talha/crash_monitor
cd crash_monitor
cargo +nightly-i686-pc-windows-msvc build --release
```
Execute crash_montior.exe with Administrator rights or in elevated powershell run.
```
crash_monitor.exe
> vulnserver.exe # give a process to monitor for crashes
```

## Example run with Boofuzz
An example boofuzz file to fuzz vulnserver can be found [here](boofuzz_fuzzer.py). Edit the IP and PORT for your configuration.

Execute crash_montior.exe with Administrator rights or in elevated powershell run.
```
crash_monitor.exe
> C:\path\to\vulnserver.exe # path to the target program
```

Run the fuzzer.
```
pip3 install boofuzz==0.4.1
py -3 boofuzz_fuzzer.py
```

## TODO
* Implement x64-bit support
* Improve synchronization 

## Limitations
* This project only support debugging 32-bit windows processes for now.

## References
* https://github.com/OpenRCE/pydbg
* https://github.com/gamozolabs/mesos
