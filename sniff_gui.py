# coding: latin-1
import threading
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import PySimpleGUI as sg
import matplotlib
import matplotlib.pyplot as plt
import sniffer as sniff

# Window theme
sg.theme('Dark Red')

# Matplotlib set figure size
plt.rcParams['figure.figsize'] = (7, 3)
matplotlib.use("TkAgg")

# Constants
protocol_names = ["TCP", "UDP", "ICMP", "Other"]
packet_headings = {
    'other_headings': ["Dest MAC", "Src MAC", "Eth Prtcl"],
    'other_headings_blankvalues': ["", "", ""],

    'IP_headings': ["Dest MAC", "Src MAC", "Eth Prtcl", "Ver",
                    "IP Hdr Lgth", "TTL", "IP Prtcl", "Src Addr", "Dest Addr"],
    'IP_headings_blankvalues': ["", "", "", "",
                                "", "", "", "", ""],
    'TCP_headings': ["Dest MAC", "Src MAC", "Eth Prtcl", "Ver",
                     "IP Hdr Lgth", "TTL", "IP Prtcl", "Src Addr", "Dest Addr",
                     "Src Port", "Dest Port", "Seq Num", "Ack", "TCP Hdr lgth"],
    'TCP_headings_blankvalues': ["", "", "", "",
                                 "", "", "", "", "",
                                 "", "", "", "", ""],
    'ICMP_headings': ["Dest MAC", "Src MAC", "Eth Prtcl", "Ver",
                      "IP Hdr Lgth", "TTL", "IP Prtcl", "Src Addr", "Dest Addr",
                      "Type", "Code", "Chksm"],
    'ICMP_headings_blankvalues': ["", "", "", "",
                                  "", "", "", "", "",
                                  "", "", ""],
    'UDP_headings': ["Dest MAC", "Src MAC", "Eth Prtcl", "Ver",
                     "IP Hdr Lgth", "TTL", "IP Prtcl", "Src Addr", "Dest Addr",
                     "Src Port", "Dest Port", "Lgth", "Chksm"],
    'UDP_headings_blankvalues': ["", "", "", "",
                                 "", "", "", "", "",
                                 "", "", "", ""]
}


def update_graphic(fig, ax):
    amount_of_packets = [len(sniff.ip_tcp_packets), len(sniff.ip_udp_packets),
                         len(sniff.ip_icmp_packets), len(sniff.ip_other_packets)]
    # Reset axis
    ax.cla()
    ax.set_title("Ammount of packets per protocol")
    ax.set_ylabel("Protocols")
    plt.bar(protocol_names, amount_of_packets)
    fig.canvas.draw()


def get_data(packets):
    data = [list(x.values()) for x in packets]
    return data


def hide_tables(window):
    window['-TABLE_TCP-'].update(visible=False)
    window['-TABLE_UDP-'].update(visible=False)
    window['-TABLE_ICMP-'].update(visible=False)
    window['-TABLE_OTHER-'].update(visible=False)


# print(get_data(sniff.ip_tcp_packets))
other_table = sg.Table(
    values=[["" for i in range(len(packet_headings['other_headings']))]],
    headings=packet_headings['other_headings'],
    max_col_width=25,
    auto_size_columns=True,
    display_row_numbers=False,
    vertical_scroll_only=False,
    justification='right',
    num_rows=10,
    alternating_row_color='lightyellow',
    key='-TABLE_OTHER-',
    row_height=25,
    tooltip='Other packets table')

tcp_table = sg.Table(
    values=[packet_headings['TCP_headings_blankvalues']],
    headings=packet_headings['TCP_headings'],
    max_col_width=40,
    # background_color='light blue',
    visible=False,
    auto_size_columns=True,
    display_row_numbers=False,
    vertical_scroll_only=False,
    justification='right',
    num_rows=10,
    alternating_row_color='lightyellow',
    key='-TABLE_TCP-',
    row_height=25,
    tooltip='TCP packets table')

udp_table = sg.Table(
    values=[packet_headings['UDP_headings_blankvalues']],
    headings=packet_headings['UDP_headings'],
    max_col_width=40,
    # background_color='light blue',
    visible=False,
    auto_size_columns=True,
    display_row_numbers=False,
    vertical_scroll_only=False,
    justification='right',
    num_rows=10,
    alternating_row_color='lightyellow',
    key='-TABLE_UDP-',
    row_height=25,
    tooltip='UDP packets table')
icmp_table = sg.Table(
    values=[packet_headings['ICMP_headings_blankvalues']],
    headings=packet_headings['ICMP_headings'],
    max_col_width=40,
    visible=False,
    auto_size_columns=True,
    display_row_numbers=False,
    vertical_scroll_only=False,
    justification='right',
    num_rows=10,
    alternating_row_color='lightyellow',
    key='-TABLE_ICMP-',
    row_height=25,
    tooltip='ICMP packets table')

layout = [
    [sg.Text("Plot test")],
    [sg.Graph((600, 400), (0, 0), (600, 400), key='Graph')],
    [sg.Button("TCP"), sg.Button("UDP"),
     sg.Button("ICMP"), sg.Button("Other")],
    [icmp_table, udp_table, tcp_table, other_table]
]

window = sg.Window("Packet sniffer",
                   layout,
                   resizable=True,
                   location=(0, 0),
                   finalize=True,
                   element_justification="center",
                   font="Helvetica 10",
                   )


# Get Matplotlib handles
fig, ax = plt.subplots()

# Link matplotlib to PySimpleGUI Graph
canvas = FigureCanvasTkAgg(fig, window['Graph'].Widget)
plot_widget = canvas.get_tk_widget()
plot_widget.grid(row=0, column=0)

# start sniffing thread
sniff_thread = threading.Thread(target=sniff.loop)
sniff_thread.start()

# ------ Event Loop ------
while True:
    # change timeout for graph refresh
    event, values = window.read(timeout=2000)
    # print(event, values)
    if event in (sg.WIN_CLOSED, 'Exit'):
        sniff._is_running = False
        sniff_thread.join()
        break

    if event == 'TCP':
        hide_tables(window)
        window['-TABLE_TCP-'].update(visible=True)
        if len(sniff.ip_tcp_packets) > 0:
            window['-TABLE_TCP-'].update(values=get_data(sniff.ip_tcp_packets))
        else:
            window['-TABLE_TCP-'].update(
                values=[packet_headings['TCP_headings_blankvalues']])

    elif event == 'UDP':
        hide_tables(window)
        window['-TABLE_UDP-'].update(visible=True)
        if len(sniff.ip_udp_packets) > 0:
            window['-TABLE_UDP-'].update(
                values=get_data(sniff.ip_udp_packets))
        else:
            window['-TABLE_UDP-'].update(
                values=[packet_headings['UDP_headings_blankvalues']])

    elif event == 'ICMP':
        hide_tables(window)
        window['-TABLE_ICMP-'].update(visible=True)
        if len(sniff.ip_icmp_packets) > 0:
            window['-TABLE_ICMP-'].update(
                values=get_data(sniff.ip_icmp_packets))
        else:
            window['-TABLE_ICMP-'].update(
                values=[packet_headings['ICMP_headings_blankvalues']])

    elif event == 'Other':
        hide_tables(window)
        window['-TABLE_OTHER-'].update(visible=True)
        if len(sniff.ip_icmp_packets) > 0:
            window['-TABLE_ICMP-'].update(
                values=get_data(sniff.ip_other_packets))
        else:
            window['-TABLE_ICMP-'].update(
                values=[packet_headings['other_headings_blankvalues']])

    # Draw graph
    update_graphic(fig, ax)

# Close window on exit
window.close()
