### Critical Rules for developers
- Please always follow CONTRIBUTING.md and CODE_OF_CONDUCT.md


## Github

### repos

- https://github.com/openthread/openthread is the repo of OpenThread
- https://github.com/zesonzhang/openthread is my forked repo from https://github.com/openthread/openthread, it's the main repo that I am working on to create PRs


## RCP Firmware functional test

tools/cp-caps is the tool to test Thread RCP (radio co-processor) FW functions.

### Enviroment setup

1. Create Python venv: `python3 -m venv .venv`
2. Activate: `source .venv/bin/activate`
3. Install dependencies (only once):

```
pip3 install -r ./tools/cp-caps/requirements.txt
pip3 install -e ./tools/otci
```

### Hardware

We will use two devices to perform the cp-caps test:

1. DUT (device-under-test): it's usually a Thread Border Router to be tested
    - We use ADB to control DUT, we can get the device serial number by running `adb devices`
    - My Eilish P1 device adb serial number is `4A081Y7CZ01071`
2. Reference device: nRF52840DK, it's the development board by Nordic, it's running as a Thread FTD.
    - The reference device will be "/dev/ttyACM[012]", usually /dev/ttyACM1.

### environment variables

- DEBUG: this is optional, "DEBUG=on" to enable debug logging
- DUT_ADB_USB: must have, the value the adb device serial number, e.g. "DUT_ADB_USB=4A081Y7CZ01071"
- REF_CLI_SERIAL: must have, e.g. "REF_CLI_SERIAL=/dev/ttyACM1"

### Critical rules for running cp-caps
- Ensure you have active the python venv before running any cp-caps tests
- Ensure the python venv dependencies are all installed. If you are not sure, just install them.
- Always check the DUT existence and its serial number by using `adb devices` before running the tests
- Always check the reference device existence (check /dev/ttyACM*) before running the tests. If you are not sure which device to use, ask me.
- After checking the DUT existence and before running the tests, you will need to run `adb kill-server` to ensure the test script can takeover the ADB access.


### Run test cases

You can list all the `test_*.py` files under tools/cp-caps to see what are the test classes. For each test class, you can read the file content to know what are the detailed test cases inside a test class.

Here are some examples to run a test:

- Run diag commands test:
```
DUT_ADB_USB=4A081Y7CZ01071 REF_CLI_SERIAL=/dev/ttyACM1 python tools/cp-caps/test_diag_commands.py
```

- Run diag commands test with debug mode on
```
DEBUG=on DUT_ADB_USB=4A081Y7CZ01071 REF_CLI_SERIAL=/dev/ttyACM1 python tools/cp-caps/test_diag_commands.py
```

- Run single test_diag_send test case only in diag commands tests:
```
DUT_ADB_USB=4A081Y7CZ01071 REF_CLI_SERIAL=/dev/ttyACM1 python3 tools/cp-caps/test_diag_commands.py TestDiagCommands.test_diag_send
```
