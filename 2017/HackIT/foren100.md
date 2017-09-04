This challenge provided me with a .pcap and not much more information. I began by loading it into wireshark and sorting the packets by length to find the ones with the most information. One of these packets held the text “Apple Keyboard.” Looks like we're dealing with a HID keyboard. 
I googled around and found the HID keyboard codes (http://www.freebsddiary.org/APC/usb_hid_usages.php), now the challenge becomes a matter of converting the codes to the proper keys.
```
no_shift = {
    "00": "",
    "01": "",
    "02": "",
    "02": "",
    "03": "",
    "04": "a",
    "05": "b",
    "06": "c",
    "07": "d",
    "08": "e",
    "09": "f",
    "0a": "g",
    "0b": "h",
    "0c": "i",
    "0d": "j",
    "0e": "k",
    "0f": "l",
    "10": "m",
    "11": "n",
    "12": "o",
    "13": "p",
    "14": "q",
    "15": "r",
    "16": "s",
    "17": "t",
    "18": "u",
    "19": "v",
    "1a": "w",
    "1b": "x",
    "1c": "y",
    "1d": "z",
    "1e": "1",
    "1f": "2",
    "20": "3",
    "21": "4",
    "22": "5",
    "23": "6",
    "24": "7",
    "25": "8",
    "26": "9",
    "27": "0",
    "28": "\n",
    "29": "<ESC>",
    "2a": "<DEL>",
    "2b": "<TAB>",
    "2c": " ",
    "2d": "-",
    "2e": "=",
    "2f": "[",
    "30": "]",
    "37": ".",
    "51": "↓",
    "52": "↑"
}
```
I extracted the capture data with tshark: 
```
tshark -r task.pcap -Y "frame.len==35" -T fields -e usb.capdata > data.txt
```
I loaded this file into a simple python script to extract the important values based on their location in the string, and compared them to the HID codes, checking whether the shift modifer was pressed. At first glance, this output was useless. 
```
w
k
f
b
3↑[↑l↑#↑{w$↓b↓ag↓[e↓ci[↑[f↑{k↑n$↑ju}↓↓3↓u↓%=↑↑y↑6↑↓p↓b↓7↓%&↑d↑0↑j↑pt↓i↓a↓[↓k(↑=↑r↑m↑]=↓0↓d↓↓lc↑*↑_↑{↑j%↓u↓s↓(↓*2↑0↑n↑↑9↓h↓4↓]↓y4↑↑k↑↑+p↓f↓e↓$↓!}↑1↑_↑k↑s&↓s↓2↓c↓%q↑$↑.↑!↑#↓s↓0↓c↓z3↑e↑}↑-↑i
```
But when I realized the excess number of arrow key inputs were important, we found the solution.
By keeping track of which line we are on, we can only print the important line, and voila, a flag!
```
flag{k3yb0ard_sn4ke_2.0}
```
```
#!/usr/bin/python

import sys

shift_translation = {
    "00": "",
    "01": "",
    "02": "",
    "02": "",
    "03": "",
    "04": "A",
    "05": "B",
    "06": "C",
    "07": "D",
    "08": "E",
    "09": "F",
    "0a": "G",
    "0b": "H",
    "0c": "I",
    "0d": "J",
    "0e": "K",
    "0f": "L",
    "10": "M",
    "11": "N",
    "12": "0",
    "13": "P",
    "14": "Q",
    "15": "R",
    "16": "S",
    "17": "T",
    "18": "U",
    "19": "V",
    "1a": "W",
    "1b": "X",
    "1c": "Y",
    "1d": "Z",
    "1e": "!",
    "1f": "@",
    "20": "#",
    "21": "$",
    "22": "%",
    "23": "^",
    "24": "&",
    "25": "*",
    "26": "(",
    "27": ")",
    "28": "\n",
    "29": "<ESC>",
    "2a": "<DEL>",
    "2b": "<TAB>",
    "2c": " ",
    "2d": "_",
    "2e": "+",
    "2f": "{",
    "30": "}",
    "37": ">",
    "51": "↓",
    "52": "↑"
}

no_shift = {
    "00": "",
    "01": "",
    "02": "",
    "02": "",
    "03": "",
    "04": "a",
    "05": "b",
    "06": "c",
    "07": "d",
    "08": "e",
    "09": "f",
    "0a": "g",
    "0b": "h",
    "0c": "i",
    "0d": "j",
    "0e": "k",
    "0f": "l",
    "10": "m",
    "11": "n",
    "12": "o",
    "13": "p",
    "14": "q",
    "15": "r",
    "16": "s",
    "17": "t",
    "18": "u",
    "19": "v",
    "1a": "w",
    "1b": "x",
    "1c": "y",
    "1d": "z",
    "1e": "1",
    "1f": "2",
    "20": "3",
    "21": "4",
    "22": "5",
    "23": "6",
    "24": "7",
    "25": "8",
    "26": "9",
    "27": "0",
    "28": "\n",
    "29": "<ESC>",
    "2a": "<DEL>",
    "2b": "<TAB>",
    "2c": " ",
    "2d": "-",
    "2e": "=",
    "2f": "[",
    "30": "]",
    "37": ".",
    "51": "↓",
    "52": "↑"
}

if len(sys.argv) < 2:
    print("Usage: ./program.py <datafile>")
    sys.exit()

with open(sys.argv[1]) as f:
    c = f.read()

lines = c.splitlines()

pos = 0

for line in lines:
    shift_enabled = "02" == line[:2] or "03" == line[:2]
    control_enabled = "01" == line[:2] or "03" == line[:2]
    if control_enabled:
        sys.stdout.write("<CTRL>")
    """
    if shift_enabled:
        sys.stdout.write("Y")
    else:
        sys.stdout.write("N")
        """
    try:
        char_code = line[6:8]
        if shift_enabled:
            translated_code = shift_translation[char_code]
        else:
            translated_code = no_shift[char_code]
    except:
        char_code = ""
        translated_code = ""

    if translated_code == "↓" or translated_code == "\n":
        pos += 1
        if pos > 4:
            pos = 4
        translated_code = ""
    if translated_code == "↑" :
        pos -= 1
        if pos < 0:
            pos = 0
        translated_code = ""

    if pos == 2:
        sys.stdout.write(translated_code)
```
