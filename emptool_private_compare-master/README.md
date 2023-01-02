# emptool_private_compare


## how to build 

### emp_tool
```
cd emp
python install.py --deps --tool --ot --sh2pc
```

### private compare
```
cd build && cmake ..
make
```

## how to use
```
export party_port=12345
export p1_input=//some number
export p2_input=//some number
./test 1 ${party_port} ${p1_input} & ./test 2 ${party_port} ${p2_input}
```
