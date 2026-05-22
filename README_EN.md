# DMS

Distributed Memory Service (DMS) is a foundational component providing distributed memory services.<br>
It supports the transmission of PAGE content over TCP/RDMA networks, merging primary and standby memory to provide real-time page exchange capabilities. This enables real-time consistent read functionality on standby nodes.
#### 1. Project Description
##### 1. Programming language: C
##### 2. Compilation tool: CMake (recommended) or Make
##### 3. Directories:
-   `DMS`: the main directory. The `CMakeLists.txt` file is the main project entry.
-   `src`: the source code directory. Common functions are grouped by sub-directory.
-   `build`: the project building script

#### 2. Compilation Guide
##### 1. OS and Software Dependencies
The following OSs are supported:
-   CentOS 7.6 (x86)
-   openEuler 20.03 LTS
-   openEuler 22.03 LTS
-   openEuler 24.03 LTS

For details about how to adapt to other OSs, see the openGauss compilation guide.
##### 2. Downloading DMS
Download DMS from the open-source community.
##### 3. Compiling Code
Use `DMS/build/linux/opengauss/build.sh` to compile the code. The following table describes the parameters.<br>
| Option| Parameter              | Description                                  |
| ---  |:---              | :---                                   |
| -3rd | [binarylibs path] | Specifies the `binarylibs` path. It must be an absolute path.|
| -m | [version_mode] | Specifies the target version of the compilation. It can be `Debug` or `Release` (default).|
| -t   | [build_tool]      | Specifies the compilation tool, which can be `cmake` (default) or `make`.|

Run the following command to perform compilation:<br>
`[user@linux ]$ sh build.sh -3rd [binarylibs path] -m Release -t cmake`<br>
After the compilation is complete, the dynamic library is generated under the `DMS/output/lib` directory.
