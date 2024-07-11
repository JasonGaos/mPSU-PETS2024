# Toward a Multi-party Private Set Union

**!! Requirement: C++14, CMake >= 3.18**

## Make script files runable
```
sudo chmod +x build.sh libOTe_install.sh emp_install.sh run.sh
```

## 1. Install libOTe
This step is important, to install libOTe and related packages (relic, boost, sodium)

```
./libOTe_install.sh
```

## 2. Install emp-toolkit 

This step is for us to install emp-tool, emp-ot, emp-sh2pc. Note that we also modify the code of emp-tool so that it is compatible with libOTe

```
./emp_install.sh
```

## 3. Build Script and Run

### Build
```
./build.sh
```

### Run
```
./run.sh
```