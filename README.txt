before you use this tool you have to install everything requiered and run this so the 
tool will work 

cd ~/nighthawk

ls tools/   # confirm the files actually moved

python3 - <<'PY'
import pathlib, re

menu = pathlib.Path("night_hawk.py")
src = menu.read_text()
src = re.sub(r'"(?:tools/)?(dos_tool\.py|sql_injection\.py|ip_rotation\.py)"',
             r'"tools/\1"', src)
menu.write_text(src)

sqli = pathlib.Path("tools/sql_injection.py")
code = sqli.read_text()
code = code.replace(
    'name = os.path.join(HERE, f"sqli_report_{stamp}.txt")',
    'name = os.path.join(os.path.dirname(HERE), "reports", f"sqli_report_{stamp}.txt")'
)
sqli.write_text(code)
print("patched")
PY

grep -n 'tools/' night_hawk.py
python3 -m py_compile night_hawk.py tools/sql_injection.py && echo "compile OK"
./nh


#Script:2

cd ~/nighthawk

python3 - <<'PY'
import pathlib
p = pathlib.Path("night_hawk.py")
s = p.read_text()
needle = '("RED TEAM CYBERSECURITY", "DOS"): "tools/dos_tool.py",'
line = '\n    ("RED TEAM CYBERSECURITY", "Admin Panel Finder"): "tools/admin_finder.py",'
if "admin_finder.py" not in s:
    s = s.replace(needle, needle + line)
    p.write_text(s)
    print("wired")
else:
    print("already wired")
PY

python3 -m py_compile tools/admin_finder.py night_hawk.py && echo "compile OK"
./nh


#script:3

cd ~/nighthawk
ls -la

cat <<'EOF' > nh
#!/usr/bin/env bash
cd "$(dirname "$(realpath "$0")")" || exit 1
exec python3 night_hawk.py "$@"
EOF

chmod +x nh
./nh


#then-do

cd ~/nighthawk
mkdir -p tools reports

python3 - <<'PY'
import pathlib
p = pathlib.Path("night_hawk.py")
s = p.read_text()
old_line = '    ("RED TEAM CYBERSECURITY", "Hash Cracker"): "tools/hash_cracker.py",'
new_line = '    ("RED TEAM CYBERSECURITY", "Hash Cracking"): "tools/hash_cracker.py",'
needle = '("RED TEAM CYBERSECURITY", "DOS"): "tools/dos_tool.py",'
if old_line in s:
    s = s.replace(old_line, new_line)
    p.write_text(s)
    print("fixed key to Hash Cracking")
elif new_line not in s:
    s = s.replace(needle, needle + "\n" + new_line)
    p.write_text(s)
    print("wired")
else:
    print("already wired")
PY

python3 -m py_compile tools/hash_cracker.py night_hawk.py && echo "compile OK"
python3 night_hawk.py

#script-5:

cd ~/nighthawk
mkdir -p tools reports

python3 - <<'PY'
import pathlib

p = pathlib.Path("Night_Hawk.py")
s = p.read_text()

old_line = '    ("OPSEC", "Use Tor Network"): "tools/ip_rotation.py",'
new_line = '    ("OPSEC", "Use Tor Network"): "tools/tor_router.py",'
needle = '    ("OPSEC", "IP Rotation"): "tools/ip_rotation.py",'

if old_line in s:
    s = s.replace(old_line, new_line)
    p.write_text(s)
    print("fixed Tor mapping")
elif new_line not in s:
    if needle not in s:
        raise SystemExit("Could not find the OPSEC IP Rotation mapping.")
    s = s.replace(needle, needle + "\n" + new_line, 1)
    p.write_text(s)
    print("wired Tor router")
else:
    print("already wired")
PY

python3 -m py_compile tools/tor_router.py Night_Hawk.py && echo "compile OK"
python3 Night_Hawk.py

#script-6:

cd ~/nighthawk

python3 - <<'PY'
import pathlib

p = pathlib.Path("Night_Hawk.py")
s = p.read_text()

old = '    ("OPSEC", "MAC Spoofing"): "tools/mac_spoof.py",'
new = '    ("OPSEC", "Spoof MAC"): "tools/mac_spoof.py",'

if new in s:
    print("already fixed")
elif old in s:
    s = s.replace(old, new)
    p.write_text(s)
    print("fixed key: MAC Spoofing -> Spoof MAC")
else:
    raise SystemExit("Could not find the MAC mapping line.")
PY

python3 -m py_compile Night_Hawk.py tools/mac_spoof.py && echo "compile OK"
sudo python3 Night_Hawk.py

#script-7:

python3 - <<'PY'
import pathlib

p = pathlib.Path("Night_Hawk.py")
s = p.read_text()

anchor = '    ("OPSEC", "Use Tor Network"): "tools/tor_router.py",'
new_line = '    ("OPSEC", "Use Proxy"): "tools/proxy.py",'

if new_line in s:
    print("already wired")
elif anchor in s:
    s = s.replace(anchor, anchor + "\n" + new_line, 1)
    p.write_text(s)
    print("wired proxy tool")
else:
    raise SystemExit("Could not find the Tor mapping to anchor against.")
PY
