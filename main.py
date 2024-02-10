import customtkinter
import frida
from customtkinter import *

session: frida.core.Session
fun = 0x0
app = CTk()
parse_total = 0
time_elapsed = 0
last_timer_mem = 0x0
parse_text = "%s:%s  -  %s  -  %s DPS"


def scan(pattern):
    # code from poxyran/misc
    script = session.create_script("""
        var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
        var range;

        function processNext(){
            var match = false;
            
            range = ranges.pop();
            if (!range) {
                return;
            }

            Memory.scan(range.base, range.size, '%s', {
                onMatch: function(address, size) {
                    send(address.toString());
                    match = true;
                    return "stop";
                }, 
                onError: function(reason){
                    console.log('[!] There was an error scanning memory');
                }, 
                onComplete: function(){
                    if (match == true) { return; }
                    processNext();
                }
            });
        }
        
        processNext();
    """ % pattern)

    script.on('message', on_scan_msg)
    script.load()


def on_scan_msg(message, data):
    global fun
    fun = int(message["payload"], 16) + 0x7     # arbitrary offset
    # print("Pattern matched at address %s" % hex(fun))
    read(fun)


def read(address):
    script = session.create_script("""
        Interceptor.attach(ptr("0x%x"), {
            onEnter(args) {
                var x = this.context;
                send(x);
            }
        });
    """ % address)

    script.on('message', on_read_msg)
    script.load()


def on_read_msg(message, data):
    rax = int(message["payload"]["rax"], 16)
    if rax == 0:
        return

    rsi = message["payload"]["rsi"]

    global last_timer_mem
    global time_elapsed
    global parse_total

    if rax >= 9999999:
        if last_timer_mem != rsi and last_timer_mem != 1:
            last_timer_mem = rsi
            time_elapsed = 0
            parse_total = 0
        else:
            time_elapsed += 1
            update()
    else:
        parse_total += rax
        # print("rsi: %s -> %s" % (rsi, rax))
        update()


def reset(event):
    global last_timer_mem
    global time_elapsed
    global parse_total
    last_timer_mem = 1
    time_elapsed = 0
    parse_total = 0
    update(1)


def main():
    global session
    try:
        session = frida.attach("granblue_fantasy_relink.exe")
    except frida.ProcessNotFoundError:
        gui(True)
        return

    scan("FF 50 78 8B 44 24 40 89 87 D0 00 00 00 45 85 E4 74 6C")       # damage
    scan("BE AC 02 00 00 74 71 89 BE AC 02 00 00 8D 47 FF")             # timer
    gui()


def gui(err=False):
    app.geometry("450x100")
    app.attributes("-topmost", True)
    app.title("Scuffed GBFR Parser")

    if err:
        app.label = CTkLabel(
            master=app,
            text="GBFR process not found!!\nLaunch your game before launching the parser.",
            font=("Arial", 20))
        app.label.place(relx=0.5, rely=0.5, anchor="center")

    else:
        app.label = CTkLabel(master=app, text=parse_text % (0, "00", 0, 0), font=("Arial", 20))
        app.label.place(relx=0.5, rely=0.3, anchor="center")

        app.button = CTkButton(master=app, text="Reset")
        app.button.place(relx=0.5, rely=0.7, anchor="center")
        app.button.bind("<Button-1>", reset)

    app.mainloop()


def update(r=0):
    if r:
        app.label.configure(text=parse_text % (0, "00", 0, 0))
        return

    seconds = time_elapsed % 60 if time_elapsed % 60 > 9 else "0%s" % (time_elapsed % 60)
    damage = parse_total
    dps = parse_total // time_elapsed if int(seconds) > 0 else damage
    app.label.configure(text=parse_text % (
        time_elapsed // 60,
        seconds,
        f"{damage:,}",
        f"{dps:,}"))


if __name__ == '__main__':
    customtkinter.set_appearance_mode("Dark")
    main()

