#!/usr/bin/python3
# TOMCAT C2 Frameworks
# Author: TOM7
# GitHub: tom7voldemort

"""
[+] NOTE:
    -- Copying without owner permission is illegal.
    -- If you want to expand this project, ask owner for collaboration instead.

    Thanks for understanding.
    ~TOM7
"""

import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext, ttk, filedialog


class ToastNotification:
    def __init__(self, Parent, Colors):
        self.Parent = Parent
        self.Colors = Colors
        self.Queue = []
        self.Active = False

    def Show(self, Message, Level="info"):
        self.Queue.append((Message, Level))
        if not self.Active:
            self.ProcessQueue()

    def ProcessQueue(self):
        if not self.Queue:
            self.Active = False
            return
        self.Active = True
        Message, Level = self.Queue.pop(0)
        ColorMap = {
            "info": self.Colors["accent"],
            "success": self.Colors["green"],
            "error": self.Colors["red"],
            "warning": self.Colors["yellow"],
        }
        Bg = ColorMap.get(Level, self.Colors["accent"])
        Toast = tk.Toplevel(self.Parent)
        Toast.overrideredirect(True)
        Toast.attributes("-topmost", True)
        Toast.configure(bg=Bg)
        Px = self.Parent.winfo_x() + self.Parent.winfo_width() - 320
        Py = self.Parent.winfo_y() + 60
        Toast.geometry(f"300x40+{Px}+{Py}")
        tk.Label(
            Toast,
            text=Message,
            font=("Segoe UI", 9),
            fg="#ffffff",
            bg=Bg,
            anchor="w",
            padx=12,
        ).pack(fill=tk.BOTH, expand=True)
        Toast.after(2500, lambda: self.Dismiss(Toast))

    def Dismiss(self, Toast):
        try:
            Toast.destroy()
        except Exception:
            pass
        self.Parent.after(200, self.ProcessQueue)


class StatCard(tk.Canvas):
    def __init__(self, Parent, Title, Value, Icon, Color, Bg, **Kwargs):
        super().__init__(Parent, highlightthickness=0, bg=Bg, **Kwargs)
        self.Title = Title
        self.Value = Value
        self.Icon = Icon
        self.Color = Color
        self.Bg = Bg
        self.bind("<Configure>", self.Redraw)

    def Redraw(self, Event=None):
        self.delete("all")
        W = self.winfo_width()
        H = self.winfo_height()
        self.RoundRect(2, 2, W - 2, H - 2, 8, self.Bg, "#30363d")
        self.create_text(
            16,
            H // 2 - 2,
            text=self.Icon,
            font=("Segoe UI", 18),
            fill=self.Color,
            anchor="w",
        )
        self.create_text(
            50,
            H // 2 - 10,
            text=self.Title,
            font=("Segoe UI", 8),
            fill="#8b949e",
            anchor="w",
        )
        self.create_text(
            50,
            H // 2 + 10,
            text=str(self.Value),
            font=("Segoe UI", 14, "bold"),
            fill=self.Color,
            anchor="w",
        )

    def RoundRect(self, X1, Y1, X2, Y2, R, Fill, Outline):
        self.create_arc(
            X1,
            Y1,
            X1 + 2 * R,
            Y1 + 2 * R,
            start=90,
            extent=90,
            fill=Fill,
            outline=Outline,
        )
        self.create_arc(
            X2 - 2 * R,
            Y1,
            X2,
            Y1 + 2 * R,
            start=0,
            extent=90,
            fill=Fill,
            outline=Outline,
        )
        self.create_arc(
            X1,
            Y2 - 2 * R,
            X1 + 2 * R,
            Y2,
            start=180,
            extent=90,
            fill=Fill,
            outline=Outline,
        )
        self.create_arc(
            X2 - 2 * R,
            Y2 - 2 * R,
            X2,
            Y2,
            start=270,
            extent=90,
            fill=Fill,
            outline=Outline,
        )
        self.create_rectangle(X1 + R, Y1, X2 - R, Y2, fill=Fill, outline="")
        self.create_rectangle(X1, Y1 + R, X2, Y2 - R, fill=Fill, outline="")
        self.create_line(X1 + R, Y1, X2 - R, Y1, fill=Outline)
        self.create_line(X1 + R, Y2, X2 - R, Y2, fill=Outline)
        self.create_line(X1, Y1 + R, X1, Y2 - R, fill=Outline)
        self.create_line(X2, Y1 + R, X2, Y2 - R, fill=Outline)

    def UpdateValue(self, NewValue):
        self.Value = NewValue
        self.Redraw()


class ActivityGraph(tk.Canvas):
    def __init__(self, Parent, Colors, **Kwargs):
        super().__init__(Parent, highlightthickness=0, bg=Colors["bg2"], **Kwargs)
        self.Colors = Colors
        self.DataPoints = [0] * 60
        self.MaxVal = 1
        self.bind("<Configure>", self.Redraw)

    def AddPoint(self, Value):
        self.DataPoints.append(Value)
        if len(self.DataPoints) > 60:
            self.DataPoints.pop(0)
        self.MaxVal = max(max(self.DataPoints), 1)
        self.Redraw()

    def Redraw(self, Event=None):
        self.delete("all")
        W = self.winfo_width()
        H = self.winfo_height()
        if W < 10 or H < 10:
            return
        Padding = 8
        GraphW = W - Padding * 2
        GraphH = H - Padding * 2
        for I in range(5):
            Y = Padding + (GraphH * I // 4)
            self.create_line(Padding, Y, W - Padding, Y, fill="#21262d", dash=(2, 4))
        if len(self.DataPoints) < 2:
            return
        Points = []
        for I, Val in enumerate(self.DataPoints):
            X = Padding + (I * GraphW / (len(self.DataPoints) - 1))
            Y = Padding + GraphH - (Val / self.MaxVal * GraphH)
            Points.append((X, Y))
        FillPoints = list(Points) + [
            (W - Padding, Padding + GraphH),
            (Padding, Padding + GraphH),
        ]
        FlatFill = [Coord for P in FillPoints for Coord in P]
        if len(FlatFill) >= 6:
            self.create_polygon(FlatFill, fill="#1a3a2a", outline="", smooth=True)
        FlatLine = [Coord for P in Points for Coord in P]
        if len(FlatLine) >= 4:
            self.create_line(FlatLine, fill=self.Colors["green"], width=2, smooth=True)


class TOMCATC2GUI:
    def __init__(self):
        self.Server = None
        self.ServerStartTime = None
        self.Root = tk.Tk()
        self.Root.title("TOMCAT C2 Framework V2")
        self.Root.geometry("1200x750")
        self.Root.minsize(1000, 600)
        self.Root.configure(bg="#0a0e14")
        self.Sessions = []
        self.Logs = []
        self.CommandHistory = []
        self.HistoryIndex = -1
        self.UpdateRunning = True
        self.CurrentPage = "dashboard"
        self.PageFrames = {}
        self.SidebarButtons = {}
        self.Colors = {
            "bg": "#0a0e14",
            "bg2": "#131920",
            "bg3": "#1c2333",
            "bg4": "#242e3d",
            "sidebar": "#0d1117",
            "accent": "#58a6ff",
            "green": "#3fb950",
            "red": "#f85149",
            "yellow": "#d29922",
            "orange": "#db6d28",
            "purple": "#bc8cff",
            "text": "#f0f6fc",
            "text2": "#8b949e",
            "text3": "#484f58",
            "border": "#21262d",
        }
        self.Toast = ToastNotification(self.Root, self.Colors)
        self.ConfigureStyles()
        self.BuildLayout()

    def ConfigureStyles(self):
        S = ttk.Style()
        S.theme_use("clam")
        S.configure("Main.TFrame", background=self.Colors["bg"])
        S.configure("Card.TFrame", background=self.Colors["bg2"])
        S.configure("Sidebar.TFrame", background=self.Colors["sidebar"])
        S.configure("Inner.TFrame", background=self.Colors["bg3"])
        S.configure(
            "Main.TLabel",
            background=self.Colors["bg"],
            foreground=self.Colors["text"],
            font=("Segoe UI", 9),
        )
        S.configure(
            "Card.TLabel",
            background=self.Colors["bg2"],
            foreground=self.Colors["text"],
            font=("Segoe UI", 9),
        )
        S.configure(
            "Title.TLabel",
            background=self.Colors["bg"],
            foreground=self.Colors["accent"],
            font=("Segoe UI", 16, "bold"),
        )
        S.configure(
            "Subtitle.TLabel",
            background=self.Colors["bg"],
            foreground=self.Colors["text2"],
            font=("Segoe UI", 9),
        )
        S.configure(
            "SectionTitle.TLabel",
            background=self.Colors["bg"],
            foreground=self.Colors["text"],
            font=("Segoe UI", 11, "bold"),
        )
        S.configure(
            "Status.TLabel",
            background=self.Colors["bg2"],
            foreground=self.Colors["green"],
            font=("Segoe UI", 10, "bold"),
        )
        S.configure(
            "Footer.TLabel",
            background=self.Colors["sidebar"],
            foreground=self.Colors["text3"],
            font=("Segoe UI", 8),
        )
        S.configure(
            "Accent.TButton",
            background=self.Colors["accent"],
            foreground="#fff",
            font=("Segoe UI", 9, "bold"),
            padding=(12, 6),
        )
        S.configure(
            "Flat.TButton",
            background=self.Colors["bg3"],
            foreground=self.Colors["text"],
            font=("Segoe UI", 9),
            padding=(10, 5),
        )
        S.configure(
            "Danger.TButton",
            background=self.Colors["red"],
            foreground="#fff",
            font=("Segoe UI", 9, "bold"),
            padding=(10, 5),
        )
        S.configure(
            "Success.TButton",
            background=self.Colors["green"],
            foreground="#fff",
            font=("Segoe UI", 9, "bold"),
            padding=(10, 5),
        )
        S.configure(
            "Ghost.TButton",
            background=self.Colors["bg2"],
            foreground=self.Colors["text2"],
            font=("Segoe UI", 9),
            padding=(8, 4),
        )
        S.map("Accent.TButton", background=[("active", "#1f6feb")])
        S.map("Flat.TButton", background=[("active", "#30363d")])
        S.map("Danger.TButton", background=[("active", "#da3633")])
        S.map("Success.TButton", background=[("active", "#2ea043")])
        S.map("Ghost.TButton", background=[("active", "#1c2333")])
        S.configure(
            "Treeview",
            background=self.Colors["bg3"],
            foreground=self.Colors["text"],
            fieldbackground=self.Colors["bg3"],
            font=("Segoe UI", 9),
            rowheight=32,
            borderwidth=0,
        )
        S.configure(
            "Treeview.Heading",
            background=self.Colors["bg4"],
            foreground=self.Colors["text2"],
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
            relief="sunken",
        )
        S.map(
            "Treeview",
            background=[("selected", "#1f3a5f")],
            foreground=[("selected", self.Colors["accent"])],
        )
        S.configure("TNotebook", background=self.Colors["bg"], borderwidth=0)
        S.configure(
            "TNotebook.Tab",
            background=self.Colors["bg3"],
            foreground=self.Colors["text2"],
            font=("Segoe UI", 9),
            padding=[14, 7],
        )
        S.map(
            "TNotebook.Tab",
            background=[("selected", self.Colors["bg2"])],
            foreground=[("selected", self.Colors["accent"])],
        )
        S.configure(
            "Custom.Horizontal.TProgressbar",
            troughcolor=self.Colors["bg3"],
            background=self.Colors["accent"],
            thickness=6,
        )

    def BuildLayout(self):
        Container = tk.Frame(self.Root, bg=self.Colors["bg"])
        Container.pack(fill=tk.BOTH, expand=True)
        self.BuildSidebar(Container)
        RightSide = tk.Frame(Container, bg=self.Colors["bg"])
        RightSide.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.BuildTopBar(RightSide)
        self.ContentArea = tk.Frame(RightSide, bg=self.Colors["bg"])
        self.ContentArea.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 8))
        self.BuildDashboardPage()
        self.BuildSessionsPage()
        self.BuildTerminalPage()
        self.BuildLogsPage()
        self.BuildStatsPage()
        self.BuildSettingsPage()
        self.BuildFooter(RightSide)
        self.ShowPage("dashboard")
        self.Root.protocol("WM_DELETE_WINDOW", self.OnClose)
        self.Root.bind("<F5>", lambda E: self.RefreshSessions())
        self.Root.bind("<Control-l>", lambda E: self.ShowPage("logs"))
        self.Root.bind("<Control-t>", lambda E: self.ShowPage("terminal"))

    def BuildSidebar(self, Parent):
        Sidebar = tk.Frame(Parent, bg=self.Colors["sidebar"], width=200)
        Sidebar.pack(side=tk.LEFT, fill=tk.Y)
        Sidebar.pack_propagate(False)
        LogoFrame = tk.Frame(Sidebar, bg=self.Colors["sidebar"])
        LogoFrame.pack(fill=tk.X, padx=16, pady=(20, 6))
        tk.Label(
            LogoFrame,
            text="◉",
            font=("Segoe UI", 20),
            fg=self.Colors["red"],
            bg=self.Colors["sidebar"],
        ).pack(side=tk.LEFT)
        TitleFrame = tk.Frame(LogoFrame, bg=self.Colors["sidebar"])
        TitleFrame.pack(side=tk.LEFT, padx=(8, 0))
        tk.Label(
            TitleFrame,
            text="TOMCAT",
            font=("Segoe UI", 13, "bold"),
            fg=self.Colors["text"],
            bg=self.Colors["sidebar"],
        ).pack(anchor="w")
        tk.Label(
            TitleFrame,
            text="C2 Framework",
            font=("Segoe UI", 8),
            fg=self.Colors["text3"],
            bg=self.Colors["sidebar"],
        ).pack(anchor="w")
        tk.Frame(Sidebar, bg=self.Colors["border"], height=1).pack(
            fill=tk.X, padx=16, pady=(16, 12)
        )
        tk.Label(
            Sidebar,
            text="MAIN",
            font=("Segoe UI", 7, "bold"),
            fg=self.Colors["text3"],
            bg=self.Colors["sidebar"],
            anchor="w",
        ).pack(fill=tk.X, padx=20, pady=(0, 4))
        NavItems = [
            ("dashboard", "⊞", "Dashboard"),
            ("sessions", "⊟", "Sessions"),
            ("terminal", "⊳", "Terminal"),
            ("logs", "☰", "Logs"),
            ("stats", "◫", "Statistics"),
        ]
        for PageId, Icon, Label in NavItems:
            self.CreateSidebarButton(Sidebar, PageId, Icon, Label)
        tk.Frame(Sidebar, bg=self.Colors["border"], height=1).pack(
            fill=tk.X, padx=16, pady=(12, 12)
        )
        tk.Label(
            Sidebar,
            text="SYSTEM",
            font=("Segoe UI", 7, "bold"),
            fg=self.Colors["text3"],
            bg=self.Colors["sidebar"],
            anchor="w",
        ).pack(fill=tk.X, padx=20, pady=(0, 4))
        self.CreateSidebarButton(Sidebar, "settings", "⚙", "Settings")
        BottomFrame = tk.Frame(Sidebar, bg=self.Colors["sidebar"])
        BottomFrame.pack(side=tk.BOTTOM, fill=tk.X, padx=16, pady=16)
        tk.Frame(BottomFrame, bg=self.Colors["border"], height=1).pack(
            fill=tk.X, pady=(0, 12)
        )
        self.SidebarStatusDot = tk.Label(
            BottomFrame,
            text="●",
            font=("Segoe UI", 8),
            fg=self.Colors["red"],
            bg=self.Colors["sidebar"],
        )
        self.SidebarStatusDot.pack(side=tk.LEFT)
        self.SidebarStatusText = tk.Label(
            BottomFrame,
            text="Offline",
            font=("Segoe UI", 8),
            fg=self.Colors["text3"],
            bg=self.Colors["sidebar"],
        )
        self.SidebarStatusText.pack(side=tk.LEFT, padx=(4, 0))

    def CreateSidebarButton(self, Parent, PageId, Icon, Label):
        Btn = tk.Frame(Parent, bg=self.Colors["sidebar"], cursor="hand2")
        Btn.pack(fill=tk.X, padx=8, pady=1)
        Inner = tk.Frame(Btn, bg=self.Colors["sidebar"], padx=12, pady=8)
        Inner.pack(fill=tk.X)
        IconLabel = tk.Label(
            Inner,
            text=Icon,
            font=("Segoe UI", 11),
            fg=self.Colors["text2"],
            bg=self.Colors["sidebar"],
        )
        IconLabel.pack(side=tk.LEFT)
        TextLabel = tk.Label(
            Inner,
            text=Label,
            font=("Segoe UI", 9),
            fg=self.Colors["text2"],
            bg=self.Colors["sidebar"],
        )
        TextLabel.pack(side=tk.LEFT, padx=(10, 0))
        Indicator = tk.Frame(Inner, bg=self.Colors["sidebar"], width=3, height=20)
        Indicator.pack(side=tk.RIGHT)
        self.SidebarButtons[PageId] = {
            "Frame": Btn,
            "Inner": Inner,
            "Icon": IconLabel,
            "Text": TextLabel,
            "Indicator": Indicator,
        }
        for Widget in [Btn, Inner, IconLabel, TextLabel]:
            Widget.bind("<Button-1>", lambda E, P=PageId: self.ShowPage(P))
            Widget.bind("<Enter>", lambda E, P=PageId: self.SidebarHover(P, True))
            Widget.bind("<Leave>", lambda E, P=PageId: self.SidebarHover(P, False))

    def SidebarHover(self, PageId, Enter):
        if PageId == self.CurrentPage:
            return
        Bg = self.Colors["bg3"] if Enter else self.Colors["sidebar"]
        Fg = self.Colors["text"] if Enter else self.Colors["text2"]
        Widgets = self.SidebarButtons[PageId]
        for Key in ["Frame", "Inner", "Icon", "Text"]:
            Widgets[Key].configure(bg=Bg)
        Widgets["Icon"].configure(fg=Fg)
        Widgets["Text"].configure(fg=Fg)

    def ShowPage(self, PageId):
        PageTitles = {
            "dashboard": ("Dashboard", "Overview & Monitoring"),
            "sessions": ("Sessions", "Manage Active Connections"),
            "terminal": ("Terminal", "Remote Command Execution"),
            "logs": ("Logs", "Event History & Audit Trail"),
            "stats": ("Statistics", "Session Analytics & Breakdown"),
            "settings": ("Settings", "Server Configuration"),
        }
        for Pid, Widgets in self.SidebarButtons.items():
            IsActive = Pid == PageId
            Bg = self.Colors["bg2"] if IsActive else self.Colors["sidebar"]
            Fg = self.Colors["accent"] if IsActive else self.Colors["text2"]
            IndBg = self.Colors["accent"] if IsActive else self.Colors["sidebar"]
            for Key in ["Frame", "Inner", "Icon", "Text"]:
                Widgets[Key].configure(bg=Bg)
            Widgets["Icon"].configure(fg=Fg)
            Widgets["Text"].configure(fg=Fg)
            Widgets["Indicator"].configure(bg=IndBg)
        for Fid, Frame in self.PageFrames.items():
            Frame.pack_forget()
        if PageId in self.PageFrames:
            self.PageFrames[PageId].pack(fill=tk.BOTH, expand=True)
        if PageId in PageTitles:
            self.TopBarTitle.config(text=PageTitles[PageId][0])
            self.TopBarSub.config(text=f"  {PageTitles[PageId][1]}")
        self.CurrentPage = PageId

    def BuildTopBar(self, Parent):
        TopBar = tk.Frame(Parent, bg=self.Colors["bg2"], height=50)
        TopBar.pack(fill=tk.X)
        TopBar.pack_propagate(False)
        LeftSection = tk.Frame(TopBar, bg=self.Colors["bg2"])
        LeftSection.pack(side=tk.LEFT, fill=tk.Y, padx=16)
        self.TopBarTitle = tk.Label(
            LeftSection,
            text="Dashboard",
            font=("Segoe UI", 12, "bold"),
            fg=self.Colors["text"],
            bg=self.Colors["bg2"],
        )
        self.TopBarTitle.pack(side=tk.LEFT, pady=12)
        self.TopBarSub = tk.Label(
            LeftSection,
            text="  Overview & Monitoring",
            font=("Segoe UI", 9),
            fg=self.Colors["text3"],
            bg=self.Colors["bg2"],
        )
        self.TopBarSub.pack(side=tk.LEFT, pady=12)
        RightSection = tk.Frame(TopBar, bg=self.Colors["bg2"])
        RightSection.pack(side=tk.RIGHT, fill=tk.Y, padx=16)
        self.StatusLabel = tk.Label(
            RightSection,
            text="● Stopped",
            font=("Segoe UI", 9, "bold"),
            fg=self.Colors["red"],
            bg=self.Colors["bg2"],
        )
        self.StatusLabel.pack(side=tk.LEFT, padx=(0, 16), pady=12)
        tk.Frame(RightSection, bg=self.Colors["border"], width=1).pack(
            side=tk.LEFT, fill=tk.Y, pady=12
        )
        self.UptimeLabel = tk.Label(
            RightSection,
            text="⏱ 00:00:00",
            font=("Segoe UI", 9),
            fg=self.Colors["text2"],
            bg=self.Colors["bg2"],
        )
        self.UptimeLabel.pack(side=tk.LEFT, padx=16, pady=12)
        tk.Frame(RightSection, bg=self.Colors["border"], width=1).pack(
            side=tk.LEFT, fill=tk.Y, pady=12
        )
        self.SessionCountLabel = tk.Label(
            RightSection,
            text="⊟ 0 Sessions",
            font=("Segoe UI", 9),
            fg=self.Colors["accent"],
            bg=self.Colors["bg2"],
        )
        self.SessionCountLabel.pack(side=tk.LEFT, padx=(16, 0), pady=12)

    def BuildFooter(self, Parent):
        Footer = tk.Frame(Parent, bg=self.Colors["sidebar"], height=28)
        Footer.pack(fill=tk.X, side=tk.BOTTOM)
        Footer.pack_propagate(False)
        tk.Label(
            Footer,
            text="TOMCAT C2 Framework V2  |  Author: TOM7",
            font=("Segoe UI", 7),
            fg=self.Colors["text3"],
            bg=self.Colors["sidebar"],
        ).pack(side=tk.LEFT, padx=12)
        self.FooterClock = tk.Label(
            Footer,
            text="",
            font=("Segoe UI", 7),
            fg=self.Colors["text3"],
            bg=self.Colors["sidebar"],
        )
        self.FooterClock.pack(side=tk.RIGHT, padx=12)
        self.UpdateClock()

    def UpdateClock(self):
        Now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self.FooterClock.config(text=Now)
        self.Root.after(1000, self.UpdateClock)

    def BuildDashboardPage(self):
        Page = tk.Frame(self.ContentArea, bg=self.Colors["bg"])
        self.PageFrames["dashboard"] = Page
        CardsRow = tk.Frame(Page, bg=self.Colors["bg"])
        CardsRow.pack(fill=tk.X, pady=(12, 8))
        CardsRow.columnconfigure(0, weight=1)
        CardsRow.columnconfigure(1, weight=1)
        CardsRow.columnconfigure(2, weight=1)
        CardsRow.columnconfigure(3, weight=1)
        self.CardTotal = StatCard(
            CardsRow,
            "Total Sessions",
            0,
            "⊟",
            self.Colors["accent"],
            self.Colors["bg2"],
            height=70,
        )
        self.CardTotal.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=4)
        self.CardTomcat = StatCard(
            CardsRow,
            "TOMCAT",
            0,
            "◉",
            self.Colors["green"],
            self.Colors["bg2"],
            height=70,
        )
        self.CardTomcat.grid(row=0, column=1, sticky="nsew", padx=6, pady=4)
        self.CardMeter = StatCard(
            CardsRow,
            "Meterpreter",
            0,
            "◎",
            self.Colors["purple"],
            self.Colors["bg2"],
            height=70,
        )
        self.CardMeter.grid(row=0, column=2, sticky="nsew", padx=6, pady=4)
        self.CardShell = StatCard(
            CardsRow,
            "Reverse Shell",
            0,
            "◈",
            self.Colors["orange"],
            self.Colors["bg2"],
            height=70,
        )
        self.CardShell.grid(row=0, column=3, sticky="nsew", padx=(6, 0), pady=4)
        MiddleRow = tk.Frame(Page, bg=self.Colors["bg"])
        MiddleRow.pack(fill=tk.BOTH, expand=True, pady=8)
        MiddleRow.columnconfigure(0, weight=2)
        MiddleRow.columnconfigure(1, weight=1)
        MiddleRow.rowconfigure(0, weight=1)
        GraphFrame = tk.Frame(MiddleRow, bg=self.Colors["bg2"])
        GraphFrame.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        tk.Label(
            GraphFrame,
            text="  SESSION ACTIVITY",
            font=("Segoe UI", 9, "bold"),
            fg=self.Colors["text2"],
            bg=self.Colors["bg2"],
            anchor="w",
        ).pack(fill=tk.X, pady=(10, 0), padx=4)
        self.ActivityGraph = ActivityGraph(GraphFrame, self.Colors, height=180)
        self.ActivityGraph.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        RecentFrame = tk.Frame(MiddleRow, bg=self.Colors["bg2"])
        RecentFrame.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        tk.Label(
            RecentFrame,
            text="  RECENT EVENTS",
            font=("Segoe UI", 9, "bold"),
            fg=self.Colors["text2"],
            bg=self.Colors["bg2"],
            anchor="w",
        ).pack(fill=tk.X, pady=(10, 0), padx=4)
        self.RecentEventsText = tk.Text(
            RecentFrame,
            bg=self.Colors["bg2"],
            fg=self.Colors["text2"],
            font=("Consolas", 8),
            relief="sunken",
            padx=12,
            pady=8,
            wrap=tk.WORD,
            state=tk.DISABLED,
            cursor="arrow",
        )
        self.RecentEventsText.pack(fill=tk.BOTH, expand=True, padx=4, pady=(4, 8))
        self.RecentEventsText.tag_configure("green", foreground=self.Colors["green"])
        self.RecentEventsText.tag_configure("red", foreground=self.Colors["red"])
        self.RecentEventsText.tag_configure("blue", foreground=self.Colors["accent"])
        self.RecentEventsText.tag_configure("yellow", foreground=self.Colors["yellow"])

    def BuildSessionsPage(self):
        Page = tk.Frame(self.ContentArea, bg=self.Colors["bg"])
        self.PageFrames["sessions"] = Page
        Toolbar = tk.Frame(Page, bg=self.Colors["bg"])
        Toolbar.pack(fill=tk.X, pady=(12, 8))
        SearchFrame = tk.Frame(Toolbar, bg=self.Colors["bg3"], padx=8, pady=4)
        SearchFrame.pack(side=tk.LEFT)
        tk.Label(
            SearchFrame,
            text="🔍",
            font=("Segoe UI", 9),
            fg=self.Colors["text3"],
            bg=self.Colors["bg3"],
        ).pack(side=tk.LEFT)
        self.SearchVar = tk.StringVar()
        self.SearchVar.trace_add("write", lambda *A: self.FilterSessions())
        SearchEntry = tk.Entry(
            SearchFrame,
            textvariable=self.SearchVar,
            font=("Segoe UI", 9),
            bg=self.Colors["bg3"],
            fg=self.Colors["text"],
            insertbackground=self.Colors["text"],
            relief="sunken",
            width=25,
            bd=0,
        )
        SearchEntry.pack(side=tk.LEFT, padx=(4, 0))
        BtnFrame = tk.Frame(Toolbar, bg=self.Colors["bg"])
        BtnFrame.pack(side=tk.RIGHT)
        ttk.Button(
            BtnFrame,
            text="⟳ Refresh",
            style="Flat.TButton",
            command=self.RefreshSessions,
        ).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(
            BtnFrame,
            text="▶ Execute",
            style="Accent.TButton",
            command=self.ExecuteCommand,
        ).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(
            BtnFrame, text="⊘ Kill", style="Danger.TButton", command=self.KillSession
        ).pack(side=tk.LEFT)
        ContentRow = tk.Frame(Page, bg=self.Colors["bg"])
        ContentRow.pack(fill=tk.BOTH, expand=True)
        TreeContainer = tk.Frame(ContentRow, bg=self.Colors["bg2"])
        TreeContainer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        Cols = ("ID", "Type", "Name", "IP", "OS", "User", "Host", "Joined")
        self.SessionTree = ttk.Treeview(
            TreeContainer, columns=Cols, show="headings", height=15
        )
        Widths = {
            "ID": 45,
            "Type": 80,
            "Name": 110,
            "IP": 110,
            "OS": 90,
            "User": 80,
            "Host": 90,
            "Joined": 130,
        }
        for C in Cols:
            self.SessionTree.heading(C, text=C, anchor="w")
            self.SessionTree.column(C, width=Widths.get(C, 80), anchor="w", minwidth=40)
        Scroll = ttk.Scrollbar(
            TreeContainer, orient=tk.VERTICAL, command=self.SessionTree.yview
        )
        self.SessionTree.configure(yscrollcommand=Scroll.set)
        self.SessionTree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        Scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.SessionTree.bind("<<TreeviewSelect>>", self.OnSessionSelect)
        self.SessionTree.bind("<Button-3>", self.ShowSessionContextMenu)
        self.SessionTree.bind("<Double-1>", lambda E: self.ExecuteCommand())
        self.DetailPanel = tk.Frame(ContentRow, bg=self.Colors["bg2"], width=250)
        self.DetailPanel.pack(side=tk.RIGHT, fill=tk.Y)
        self.DetailPanel.pack_propagate(False)
        tk.Label(
            self.DetailPanel,
            text="SESSION DETAILS",
            font=("Segoe UI", 9, "bold"),
            fg=self.Colors["text2"],
            bg=self.Colors["bg2"],
        ).pack(fill=tk.X, padx=12, pady=(12, 8))
        tk.Frame(self.DetailPanel, bg=self.Colors["border"], height=1).pack(
            fill=tk.X, padx=12
        )
        self.DetailContent = tk.Frame(self.DetailPanel, bg=self.Colors["bg2"])
        self.DetailContent.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        self.DetailLabels = {}
        DetailFields = [
            "ID",
            "Type",
            "Agent",
            "IP Address",
            "OS",
            "Username",
            "Hostname",
            "Joined At",
        ]
        for Field in DetailFields:
            Wrapper = tk.Frame(self.DetailContent, bg=self.Colors["bg2"])
            Wrapper.pack(fill=tk.X, pady=3)
            tk.Label(
                Wrapper,
                text=Field,
                font=("Segoe UI", 8),
                fg=self.Colors["text3"],
                bg=self.Colors["bg2"],
            ).pack(anchor="w")
            ValLabel = tk.Label(
                Wrapper,
                text="—",
                font=("Segoe UI", 9),
                fg=self.Colors["text"],
                bg=self.Colors["bg2"],
            )
            ValLabel.pack(anchor="w")
            self.DetailLabels[Field] = ValLabel
        DetailBtnFrame = tk.Frame(self.DetailPanel, bg=self.Colors["bg2"])
        DetailBtnFrame.pack(fill=tk.X, padx=12, pady=(0, 12))
        ttk.Button(
            DetailBtnFrame,
            text="▶ Execute",
            style="Accent.TButton",
            command=self.ExecuteCommand,
        ).pack(fill=tk.X, pady=(0, 4))
        ttk.Button(
            DetailBtnFrame,
            text="⊘ Kill",
            style="Danger.TButton",
            command=self.KillSession,
        ).pack(fill=tk.X)
        self.SessionContextMenu = tk.Menu(
            self.Root,
            tearoff=0,
            bg=self.Colors["bg3"],
            fg=self.Colors["text"],
            activebackground=self.Colors["accent"],
            activeforeground="#fff",
            font=("Segoe UI", 9),
        )
        self.SessionContextMenu.add_command(
            label="▶ Execute Command", command=self.ExecuteCommand
        )
        self.SessionContextMenu.add_command(
            label="⊳ Open Terminal", command=lambda: self.OpenTerminalForSession()
        )
        self.SessionContextMenu.add_separator()
        self.SessionContextMenu.add_command(
            label="⟳ Refresh", command=self.RefreshSessions
        )
        self.SessionContextMenu.add_separator()
        self.SessionContextMenu.add_command(
            label="⊘ Kill Session", command=self.KillSession
        )

    def BuildTerminalPage(self):
        Page = tk.Frame(self.ContentArea, bg=self.Colors["bg"])
        self.PageFrames["terminal"] = Page
        TopSection = tk.Frame(Page, bg=self.Colors["bg"])
        TopSection.pack(fill=tk.X, pady=(12, 8))
        tk.Label(
            TopSection,
            text="Session ID:",
            font=("Segoe UI", 9),
            fg=self.Colors["text2"],
            bg=self.Colors["bg"],
        ).pack(side=tk.LEFT)
        self.TermSessionEntry = tk.Entry(
            TopSection,
            width=8,
            font=("Consolas", 10),
            bg=self.Colors["bg3"],
            fg=self.Colors["text"],
            insertbackground=self.Colors["text"],
            relief="sunken",
        )
        self.TermSessionEntry.pack(side=tk.LEFT, padx=(6, 12), ipady=3)
        ttk.Button(
            TopSection, text="Clear", style="Ghost.TButton", command=self.ClearTerminal
        ).pack(side=tk.RIGHT)
        ttk.Button(
            TopSection,
            text="Export",
            style="Ghost.TButton",
            command=self.ExportTerminal,
        ).pack(side=tk.RIGHT, padx=(0, 4))
        TerminalFrame = tk.Frame(Page, bg=self.Colors["bg3"], bd=0)
        TerminalFrame.pack(fill=tk.BOTH, expand=True)
        TermHeader = tk.Frame(TerminalFrame, bg="#1a1e24", height=28)
        TermHeader.pack(fill=tk.X)
        TermHeader.pack_propagate(False)
        tk.Label(
            TermHeader,
            text="  ● ● ●",
            font=("Segoe UI", 8),
            fg=self.Colors["text3"],
            bg="#1a1e24",
        ).pack(side=tk.LEFT, padx=4)
        tk.Label(
            TermHeader,
            text="TOMCAT C2 Terminal",
            font=("Segoe UI", 8),
            fg=self.Colors["text3"],
            bg="#1a1e24",
        ).pack(side=tk.LEFT, padx=8)
        self.TerminalOutput = tk.Text(
            TerminalFrame,
            bg="#0c1018",
            fg=self.Colors["green"],
            font=("Consolas", 10),
            relief="sunken",
            padx=12,
            pady=8,
            wrap=tk.WORD,
            state=tk.DISABLED,
            cursor="arrow",
            selectbackground=self.Colors["accent"],
            selectforeground="#fff",
        )
        TermScroll = ttk.Scrollbar(
            TerminalFrame, orient=tk.VERTICAL, command=self.TerminalOutput.yview
        )
        self.TerminalOutput.configure(yscrollcommand=TermScroll.set)
        self.TerminalOutput.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        TermScroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.TerminalOutput.tag_configure("prompt", foreground=self.Colors["accent"])
        self.TerminalOutput.tag_configure("error", foreground=self.Colors["red"])
        self.TerminalOutput.tag_configure("success", foreground=self.Colors["green"])
        self.TerminalOutput.tag_configure("system", foreground=self.Colors["yellow"])
        InputFrame = tk.Frame(Page, bg=self.Colors["bg3"])
        InputFrame.pack(fill=tk.X, pady=(4, 0))
        tk.Label(
            InputFrame,
            text=" ❯",
            font=("Consolas", 11, "bold"),
            fg=self.Colors["accent"],
            bg=self.Colors["bg3"],
        ).pack(side=tk.LEFT, padx=(8, 0))
        self.TerminalInput = tk.Entry(
            InputFrame,
            font=("Consolas", 10),
            bg=self.Colors["bg3"],
            fg=self.Colors["text"],
            insertbackground=self.Colors["green"],
            relief="sunken",
        )
        self.TerminalInput.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4, ipady=8)
        self.TerminalInput.bind("<Return>", self.OnTerminalSubmit)
        self.TerminalInput.bind("<Up>", self.OnHistoryUp)
        self.TerminalInput.bind("<Down>", self.OnHistoryDown)
        ttk.Button(
            InputFrame,
            text="Send",
            style="Accent.TButton",
            command=lambda: self.OnTerminalSubmit(None),
        ).pack(side=tk.RIGHT, padx=6, pady=4)

    def BuildLogsPage(self):
        Page = tk.Frame(self.ContentArea, bg=self.Colors["bg"])
        self.PageFrames["logs"] = Page
        Toolbar = tk.Frame(Page, bg=self.Colors["bg"])
        Toolbar.pack(fill=tk.X, pady=(12, 8))
        self.LogFilterVar = tk.StringVar(value="all")
        FilterOptions = [
            ("All", "all"),
            ("Success", "success"),
            ("Errors", "error"),
            ("Warnings", "warning"),
            ("Info", "info"),
        ]
        for Label, Val in FilterOptions:
            Rb = tk.Radiobutton(
                Toolbar,
                text=Label,
                variable=self.LogFilterVar,
                value=Val,
                font=("Segoe UI", 8),
                fg=self.Colors["text2"],
                bg=self.Colors["bg"],
                selectcolor=self.Colors["bg3"],
                activebackground=self.Colors["bg"],
                activeforeground=self.Colors["accent"],
                indicatoron=0,
                padx=10,
                pady=4,
                relief="sunken",
                bd=0,
                command=self.ApplyLogFilter,
            )
            Rb.pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(
            Toolbar, text="Export", style="Ghost.TButton", command=self.ExportLogs
        ).pack(side=tk.RIGHT, padx=(4, 0))
        ttk.Button(
            Toolbar, text="Clear", style="Ghost.TButton", command=self.ClearLogs
        ).pack(side=tk.RIGHT)
        self.LogText = scrolledtext.ScrolledText(
            Page,
            bg="#0c1018",
            fg=self.Colors["text"],
            font=("Consolas", 9),
            relief="sunken",
            padx=12,
            pady=8,
            wrap=tk.WORD,
        )
        self.LogText.pack(fill=tk.BOTH, expand=True)
        self.LogText.tag_configure("success", foreground=self.Colors["green"])
        self.LogText.tag_configure("error", foreground=self.Colors["red"])
        self.LogText.tag_configure("warning", foreground=self.Colors["yellow"])
        self.LogText.tag_configure("info", foreground=self.Colors["accent"])
        self.LogText.tag_configure("timestamp", foreground=self.Colors["text3"])

    def BuildStatsPage(self):
        Page = tk.Frame(self.ContentArea, bg=self.Colors["bg"])
        self.PageFrames["stats"] = Page
        self.StatsContainer = tk.Frame(Page, bg=self.Colors["bg"])
        self.StatsContainer.pack(fill=tk.BOTH, expand=True, pady=12)

    def BuildSettingsPage(self):
        Page = tk.Frame(self.ContentArea, bg=self.Colors["bg"])
        self.PageFrames["settings"] = Page
        ScrollCanvas = tk.Canvas(Page, bg=self.Colors["bg"], highlightthickness=0)
        ScrollCanvas.pack(fill=tk.BOTH, expand=True)
        Inner = tk.Frame(ScrollCanvas, bg=self.Colors["bg"])
        ScrollCanvas.create_window((0, 0), window=Inner, anchor="nw")
        Inner.bind(
            "<Configure>",
            lambda E: ScrollCanvas.configure(scrollregion=ScrollCanvas.bbox("all")),
        )
        SettingsCard = tk.Frame(Inner, bg=self.Colors["bg2"])
        SettingsCard.pack(fill=tk.X, pady=(12, 8))
        tk.Label(
            SettingsCard,
            text="Server Configuration",
            font=("Segoe UI", 11, "bold"),
            fg=self.Colors["text"],
            bg=self.Colors["bg2"],
        ).pack(anchor="w", padx=16, pady=(16, 12))
        tk.Frame(SettingsCard, bg=self.Colors["border"], height=1).pack(
            fill=tk.X, padx=16
        )
        FieldsFrame = tk.Frame(SettingsCard, bg=self.Colors["bg2"])
        FieldsFrame.pack(fill=tk.X, padx=16, pady=12)
        SettingsFields = [
            ("Host", "0.0.0.0"),
            ("Port", "4444"),
            ("Max Sessions", "100"),
            ("Timeout (s)", "30"),
        ]
        self.SettingsEntries = {}
        for Label, Default in SettingsFields:
            Row = tk.Frame(FieldsFrame, bg=self.Colors["bg2"])
            Row.pack(fill=tk.X, pady=4)
            tk.Label(
                Row,
                text=Label,
                font=("Segoe UI", 9),
                fg=self.Colors["text2"],
                bg=self.Colors["bg2"],
                width=15,
                anchor="w",
            ).pack(side=tk.LEFT)
            Entry = tk.Entry(
                Row,
                font=("Segoe UI", 9),
                bg=self.Colors["bg3"],
                fg=self.Colors["text"],
                insertbackground=self.Colors["text"],
                relief="sunken",
                width=30,
            )
            Entry.pack(side=tk.LEFT, padx=(8, 0), ipady=4)
            Entry.insert(0, Default)
            self.SettingsEntries[Label] = Entry
        SecurityCard = tk.Frame(Inner, bg=self.Colors["bg2"])
        SecurityCard.pack(fill=tk.X, pady=8)
        tk.Label(
            SecurityCard,
            text="Security",
            font=("Segoe UI", 11, "bold"),
            fg=self.Colors["text"],
            bg=self.Colors["bg2"],
        ).pack(anchor="w", padx=16, pady=(16, 12))
        tk.Frame(SecurityCard, bg=self.Colors["border"], height=1).pack(
            fill=tk.X, padx=16
        )
        SecurityInner = tk.Frame(SecurityCard, bg=self.Colors["bg2"])
        SecurityInner.pack(fill=tk.X, padx=16, pady=12)
        self.MtlsVar = tk.BooleanVar(value=False)
        tk.Checkbutton(
            SecurityInner,
            text="Enable mTLS",
            variable=self.MtlsVar,
            font=("Segoe UI", 9),
            fg=self.Colors["text"],
            bg=self.Colors["bg2"],
            selectcolor=self.Colors["bg3"],
            activebackground=self.Colors["bg2"],
            activeforeground=self.Colors["accent"],
        ).pack(anchor="w", pady=2)
        self.MeterVar = tk.BooleanVar(value=False)
        tk.Checkbutton(
            SecurityInner,
            text="Meterpreter Mode",
            variable=self.MeterVar,
            font=("Segoe UI", 9),
            fg=self.Colors["text"],
            bg=self.Colors["bg2"],
            selectcolor=self.Colors["bg3"],
            activebackground=self.Colors["bg2"],
            activeforeground=self.Colors["accent"],
        ).pack(anchor="w", pady=2)
        AboutCard = tk.Frame(Inner, bg=self.Colors["bg2"])
        AboutCard.pack(fill=tk.X, pady=8)
        tk.Label(
            AboutCard,
            text="About",
            font=("Segoe UI", 11, "bold"),
            fg=self.Colors["text"],
            bg=self.Colors["bg2"],
        ).pack(anchor="w", padx=16, pady=(16, 12))
        tk.Frame(AboutCard, bg=self.Colors["border"], height=1).pack(fill=tk.X, padx=16)
        AboutInner = tk.Frame(AboutCard, bg=self.Colors["bg2"])
        AboutInner.pack(fill=tk.X, padx=16, pady=12)
        AboutInfo = [
            ("Framework", "TOMCAT C2 V2"),
            ("Author", "TOM7"),
            ("GitHub", "tom7voldemort"),
        ]
        for Label, Value in AboutInfo:
            Row = tk.Frame(AboutInner, bg=self.Colors["bg2"])
            Row.pack(fill=tk.X, pady=2)
            tk.Label(
                Row,
                text=Label,
                font=("Segoe UI", 9),
                fg=self.Colors["text3"],
                bg=self.Colors["bg2"],
                width=12,
                anchor="w",
            ).pack(side=tk.LEFT)
            tk.Label(
                Row,
                text=Value,
                font=("Segoe UI", 9),
                fg=self.Colors["text"],
                bg=self.Colors["bg2"],
            ).pack(side=tk.LEFT)

    def GetSessionById(self, SessionId):
        if hasattr(self.Server, "GetSession"):
            return self.Server.GetSession(SessionId)
        if hasattr(self.Server, "GetAgents"):
            for S in self.Server.GetAgents():
                if S["ID"] == SessionId:
                    return S
        return None

    def FetchSessions(self):
        if not self.Server:
            return []
        if hasattr(self.Server, "GetSessions"):
            return self.Server.GetSessions()
        if hasattr(self.Server, "GetAgents"):
            return self.Server.GetAgents()
        return []

    def AddLog(self, Message):
        Ts = datetime.now().strftime("%H:%M:%S")
        Entry = f"[{Ts}] {Message}\n"
        self.Logs.append(Entry)
        Tag = None
        if "[+]" in Message:
            Tag = "success"
        elif "[!]" in Message or "[-]" in Message:
            Tag = "error"
        elif "[*]" in Message:
            Tag = "warning"
        elif "[>]" in Message or "[<]" in Message:
            Tag = "info"
        self.Root.after(0, lambda: self.InsertLog(Entry, Tag))
        self.Root.after(0, lambda: self.InsertRecentEvent(Entry, Tag))
        if len(self.Logs) > 1000:
            self.Logs.pop(0)

    def InsertLog(self, Entry, Tag):
        try:
            TsEnd = Entry.index("]") + 1
            self.LogText.insert(tk.END, Entry[: TsEnd + 1], "timestamp")
            if Tag:
                self.LogText.insert(tk.END, Entry[TsEnd + 1 :], Tag)
            else:
                self.LogText.insert(tk.END, Entry[TsEnd + 1 :])
            self.LogText.see(tk.END)
        except Exception:
            pass

    def InsertRecentEvent(self, Entry, Tag):
        try:
            self.RecentEventsText.config(state=tk.NORMAL)
            TagMap = {
                "success": "green",
                "error": "red",
                "info": "blue",
                "warning": "yellow",
            }
            TagName = TagMap.get(Tag, "blue")
            self.RecentEventsText.insert(tk.END, Entry, TagName)
            self.RecentEventsText.see(tk.END)
            Lines = int(self.RecentEventsText.index("end-1c").split(".")[0])
            if Lines > 50:
                self.RecentEventsText.delete("1.0", "2.0")
            self.RecentEventsText.config(state=tk.DISABLED)
        except Exception:
            pass

    def TerminalWrite(self, Text, Tag=None):
        self.TerminalOutput.config(state=tk.NORMAL)
        if Tag:
            self.TerminalOutput.insert(tk.END, Text, Tag)
        else:
            self.TerminalOutput.insert(tk.END, Text)
        self.TerminalOutput.see(tk.END)
        self.TerminalOutput.config(state=tk.DISABLED)

    def ServerEventHandler(self, EventType, Data):
        if EventType == "ServerStarted":
            self.AddLog(f"[+] Server started on {Data['Host']}:{Data['Port']}")
            if Data.get("Mode"):
                self.AddLog(f"[*] Mode: {Data['Mode']}")
            if Data.get("Key", "N/A") != "N/A":
                self.AddLog(f"[*] Key: {Data['Key'][:32]}...")
            self.Root.after(
                0,
                lambda: self.StatusLabel.config(
                    text="● Running", foreground=self.Colors["green"]
                ),
            )
            self.Root.after(
                0, lambda: self.SidebarStatusDot.config(fg=self.Colors["green"])
            )
            self.Root.after(0, lambda: self.SidebarStatusText.config(text="Online"))
            self.Toast.Show("Server started successfully", "success")
        elif EventType == "AgentConnected":
            self.AddLog(
                f"[+] [{Data.get('Type', 'UNKNOWN')}] Session #{Data['ID']}: {Data['AgentName']} ({Data['OS']})"
            )
            self.Root.after(0, self.RefreshSessions)
            self.Toast.Show(f"New session: {Data['AgentName']}", "success")
        elif EventType == "AgentDisconnected":
            self.AddLog(f"[-] Session #{Data['ID']} disconnected")
            self.Root.after(0, self.RefreshSessions)
            self.Toast.Show(f"Session #{Data['ID']} disconnected", "warning")
        elif EventType == "AgentRemoved":
            self.AddLog(f"[!] Session #{Data['ID']} removed")
            self.Root.after(0, self.RefreshSessions)
        elif EventType == "Error":
            self.AddLog(f"[!] Error: {Data['Message']}")
            self.Toast.Show(f"Error: {Data['Message']}", "error")

    def StartServer(
        self, Host="0.0.0.0", Port=4444, UseMTLS=False, MeterpreterMode=False
    ):
        try:
            if MeterpreterMode:
                from Cores.Systems.MultiProtocolServer import (
                    MultiProtocolServer as TOMCATC2SERVER,
                )

                self.Server = TOMCATC2SERVER(
                    Host=Host,
                    Port=Port,
                    UseMTLS=UseMTLS,
                    MeterpreterMode=MeterpreterMode,
                )
            else:
                from Cores.Systems.Server import TOMCATC2SERVER

                self.Server = TOMCATC2SERVER(Host=Host, Port=Port, UseMTLS=UseMTLS)
            self.Server.AddEventListener(self.ServerEventHandler)
            Success, Message = self.Server.StartServer()
            if not Success:
                self.AddLog(f"[!] Failed: {Message}")
                messagebox.showerror("Error", f"Failed to start server: {Message}")
                return False
            self.ServerStartTime = time.time()
            AcceptThread = threading.Thread(
                target=self.Server.AcceptConnections, daemon=True
            )
            AcceptThread.start()
            self.Server.AcceptThread = AcceptThread
            threading.Thread(target=self.UpdateLoop, daemon=True).start()
            return True
        except Exception as Error:
            self.AddLog(f"[!] Error: {Error}")
            messagebox.showerror("Error", str(Error))
            return False

    def UpdateLoop(self):
        while self.UpdateRunning:
            try:
                if self.Server and self.Server.Running and self.ServerStartTime:
                    U = int(time.time() - self.ServerStartTime)
                    UptimeStr = f"{U // 3600:02d}:{(U % 3600) // 60:02d}:{U % 60:02d}"
                    Sessions = self.FetchSessions()
                    Count = len(Sessions)
                    self.Root.after(
                        0, lambda u=UptimeStr, c=Count: self.UpdateStatusBar(u, c)
                    )
                    self.Root.after(0, lambda c=Count: self.ActivityGraph.AddPoint(c))
                    self.Root.after(0, lambda s=Sessions: self.UpdateDashboardCards(s))
                    self.Root.after(0, lambda s=Sessions: self.UpdateStatsPage(s))
                time.sleep(1)
            except Exception:
                pass

    def UpdateStatusBar(self, Uptime, Count):
        self.UptimeLabel.config(text=f"⏱ {Uptime}")
        self.SessionCountLabel.config(text=f"⊟ {Count} Sessions")

    def UpdateDashboardCards(self, Sessions):
        Total = len(Sessions)
        Tomcat = sum(1 for S in Sessions if S.get("Type", "TOMCAT") == "TOMCAT")
        Meter = sum(1 for S in Sessions if S.get("Type") == "METERPRETER")
        Shell = sum(1 for S in Sessions if S.get("Type") == "REVERSE_SHELL")
        self.CardTotal.UpdateValue(Total)
        self.CardTomcat.UpdateValue(Tomcat)
        self.CardMeter.UpdateValue(Meter)
        self.CardShell.UpdateValue(Shell)

    def UpdateStatsPage(self, Sessions):
        for Widget in self.StatsContainer.winfo_children():
            Widget.destroy()
        Total = len(Sessions)
        TypeCount = {}
        OsCount = {}
        for S in Sessions:
            T = S.get("Type", "TOMCAT")
            TypeCount[T] = TypeCount.get(T, 0) + 1
            O = S.get("OS", "Unknown")
            OsCount[O] = OsCount.get(O, 0) + 1
        Row1 = tk.Frame(self.StatsContainer, bg=self.Colors["bg"])
        Row1.pack(fill=tk.X, pady=(0, 8))
        Row1.columnconfigure(0, weight=1)
        Row1.columnconfigure(1, weight=1)
        TypeCard = tk.Frame(Row1, bg=self.Colors["bg2"])
        TypeCard.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        tk.Label(
            TypeCard,
            text="SESSION TYPES",
            font=("Segoe UI", 9, "bold"),
            fg=self.Colors["text2"],
            bg=self.Colors["bg2"],
        ).pack(anchor="w", padx=16, pady=(12, 8))
        tk.Frame(TypeCard, bg=self.Colors["border"], height=1).pack(fill=tk.X, padx=16)
        TypeInner = tk.Frame(TypeCard, bg=self.Colors["bg2"])
        TypeInner.pack(fill=tk.X, padx=16, pady=12)
        TypeColors = {
            "TOMCAT": self.Colors["green"],
            "METERPRETER": self.Colors["purple"],
            "REVERSE_SHELL": self.Colors["orange"],
        }
        for T, C in TypeCount.items():
            Row = tk.Frame(TypeInner, bg=self.Colors["bg2"])
            Row.pack(fill=tk.X, pady=3)
            tk.Label(
                Row,
                text=T,
                font=("Segoe UI", 9),
                fg=TypeColors.get(T, self.Colors["text2"]),
                bg=self.Colors["bg2"],
                width=16,
                anchor="w",
            ).pack(side=tk.LEFT)
            BarBg = tk.Frame(Row, bg=self.Colors["bg3"], height=8)
            BarBg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 8))
            Pct = C / max(Total, 1)
            BarFill = tk.Frame(
                BarBg,
                bg=TypeColors.get(T, self.Colors["accent"]),
                height=8,
                width=max(1, int(200 * Pct)),
            )
            BarFill.place(x=0, y=0, relheight=1)
            tk.Label(
                Row,
                text=str(C),
                font=("Segoe UI", 9, "bold"),
                fg=self.Colors["text"],
                bg=self.Colors["bg2"],
                width=4,
            ).pack(side=tk.RIGHT)
        OsCard = tk.Frame(Row1, bg=self.Colors["bg2"])
        OsCard.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        tk.Label(
            OsCard,
            text="OPERATING SYSTEMS",
            font=("Segoe UI", 9, "bold"),
            fg=self.Colors["text2"],
            bg=self.Colors["bg2"],
        ).pack(anchor="w", padx=16, pady=(12, 8))
        tk.Frame(OsCard, bg=self.Colors["border"], height=1).pack(fill=tk.X, padx=16)
        OsInner = tk.Frame(OsCard, bg=self.Colors["bg2"])
        OsInner.pack(fill=tk.X, padx=16, pady=12)
        for O, C in OsCount.items():
            Row = tk.Frame(OsInner, bg=self.Colors["bg2"])
            Row.pack(fill=tk.X, pady=3)
            tk.Label(
                Row,
                text=O,
                font=("Segoe UI", 9),
                fg=self.Colors["text2"],
                bg=self.Colors["bg2"],
                width=16,
                anchor="w",
            ).pack(side=tk.LEFT)
            BarBg = tk.Frame(Row, bg=self.Colors["bg3"], height=8)
            BarBg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 8))
            Pct = C / max(Total, 1)
            BarFill = tk.Frame(
                BarBg, bg=self.Colors["accent"], height=8, width=max(1, int(200 * Pct))
            )
            BarFill.place(x=0, y=0, relheight=1)
            tk.Label(
                Row,
                text=str(C),
                font=("Segoe UI", 9, "bold"),
                fg=self.Colors["text"],
                bg=self.Colors["bg2"],
                width=4,
            ).pack(side=tk.RIGHT)
        DetailCard = tk.Frame(self.StatsContainer, bg=self.Colors["bg2"])
        DetailCard.pack(fill=tk.BOTH, expand=True, pady=(0, 0))
        tk.Label(
            DetailCard,
            text="ALL SESSIONS",
            font=("Segoe UI", 9, "bold"),
            fg=self.Colors["text2"],
            bg=self.Colors["bg2"],
        ).pack(anchor="w", padx=16, pady=(12, 8))
        tk.Frame(DetailCard, bg=self.Colors["border"], height=1).pack(
            fill=tk.X, padx=16
        )
        DetailText = tk.Text(
            DetailCard,
            bg=self.Colors["bg2"],
            fg=self.Colors["text"],
            font=("Consolas", 9),
            relief="sunken",
            padx=16,
            pady=8,
            wrap=tk.WORD,
        )
        DetailText.pack(fill=tk.BOTH, expand=True)
        if Sessions:
            Header = f"  {'ID':>3}  {'Type':<14}  {'Agent':<14}  {'IP':<16}  {'OS':<10}  {'User@Host'}\n"
            DetailText.insert(tk.END, Header)
            DetailText.insert(tk.END, f"  {'─' * 80}\n")
            for S in Sessions:
                DetailText.insert(
                    tk.END,
                    f"  #{S['ID']:>3}  [{S.get('Type', 'TOMCAT'):<12}]  {S['AgentName']:<14}  {S['AgentIP']:<16}  {S['OS']:<10}  {S['User']}@{S['Hostname']}\n",
                )
        else:
            DetailText.insert(tk.END, "  No active sessions\n")
        DetailText.config(state=tk.DISABLED)

    def RefreshSessions(self):
        if not self.Server:
            return
        for I in self.SessionTree.get_children():
            self.SessionTree.delete(I)
        Sessions = self.FetchSessions()
        FilterText = self.SearchVar.get().lower() if hasattr(self, "SearchVar") else ""
        for S in Sessions:
            if FilterText:
                Searchable = f"{S['ID']} {S.get('Type', '')} {S['AgentName']} {S['AgentIP']} {S['OS']} {S['User']} {S['Hostname']}".lower()
                if FilterText not in Searchable:
                    continue
            self.SessionTree.insert(
                "",
                tk.END,
                values=(
                    S["ID"],
                    S.get("Type", "TOMCAT"),
                    S["AgentName"],
                    S["AgentIP"],
                    S["OS"],
                    S["User"],
                    S["Hostname"],
                    S["JoinedAt"],
                ),
            )

    def FilterSessions(self):
        self.RefreshSessions()

    def OnSessionSelect(self, Event):
        Sel = self.SessionTree.selection()
        if not Sel:
            return
        Values = self.SessionTree.item(Sel[0])["values"]
        if len(Values) < 8:
            return
        Mapping = {
            "ID": str(Values[0]),
            "Type": str(Values[1]),
            "Agent": str(Values[2]),
            "IP Address": str(Values[3]),
            "OS": str(Values[4]),
            "Username": str(Values[5]),
            "Hostname": str(Values[6]),
            "Joined At": str(Values[7]),
        }
        for Field, Value in Mapping.items():
            if Field in self.DetailLabels:
                self.DetailLabels[Field].config(text=Value)

    def ShowSessionContextMenu(self, Event):
        Sel = self.SessionTree.identify_row(Event.y)
        if Sel:
            self.SessionTree.selection_set(Sel)
            self.SessionContextMenu.post(Event.x_root, Event.y_root)

    def OpenTerminalForSession(self):
        Sel = self.SessionTree.selection()
        if not Sel:
            return
        Sid = str(self.SessionTree.item(Sel[0])["values"][0])
        self.TermSessionEntry.delete(0, tk.END)
        self.TermSessionEntry.insert(0, Sid)
        self.ShowPage("terminal")
        self.TerminalInput.focus_set()

    def ExecuteCommand(self):
        Sel = self.SessionTree.selection()
        if not Sel:
            messagebox.showwarning("Warning", "Select a session first")
            return
        Sid = int(self.SessionTree.item(Sel[0])["values"][0])
        AgentName = str(self.SessionTree.item(Sel[0])["values"][2])
        Win = tk.Toplevel(self.Root)
        Win.title(f"Execute — Session #{Sid} ({AgentName})")
        Win.geometry("650x450")
        Win.configure(bg=self.Colors["bg"])
        Win.transient(self.Root)
        Win.grab_set()
        HeaderFrame = tk.Frame(Win, bg=self.Colors["bg2"], height=48)
        HeaderFrame.pack(fill=tk.X)
        HeaderFrame.pack_propagate(False)
        tk.Label(
            HeaderFrame,
            text=f"⊟ Session #{Sid}",
            font=("Segoe UI", 11, "bold"),
            fg=self.Colors["accent"],
            bg=self.Colors["bg2"],
        ).pack(side=tk.LEFT, padx=16, pady=10)
        tk.Label(
            HeaderFrame,
            text=AgentName,
            font=("Segoe UI", 9),
            fg=self.Colors["text2"],
            bg=self.Colors["bg2"],
        ).pack(side=tk.LEFT, pady=10)
        OutputFrame = tk.Frame(Win, bg=self.Colors["bg"])
        OutputFrame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(8, 0))
        OutputText = tk.Text(
            OutputFrame,
            bg="#0c1018",
            fg=self.Colors["green"],
            font=("Consolas", 10),
            relief="sunken",
            padx=12,
            pady=8,
            wrap=tk.WORD,
            state=tk.DISABLED,
            selectbackground=self.Colors["accent"],
            selectforeground="#fff",
        )
        OutputScroll = ttk.Scrollbar(
            OutputFrame, orient=tk.VERTICAL, command=OutputText.yview
        )
        OutputText.configure(yscrollcommand=OutputScroll.set)
        OutputText.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        OutputScroll.pack(side=tk.RIGHT, fill=tk.Y)
        OutputText.tag_configure("prompt", foreground=self.Colors["accent"])
        OutputText.tag_configure("error", foreground=self.Colors["red"])
        OutputText.tag_configure("success", foreground=self.Colors["green"])
        InputFrame = tk.Frame(Win, bg=self.Colors["bg3"])
        InputFrame.pack(fill=tk.X, padx=12, pady=(4, 12))
        tk.Label(
            InputFrame,
            text=" ❯",
            font=("Consolas", 11, "bold"),
            fg=self.Colors["accent"],
            bg=self.Colors["bg3"],
        ).pack(side=tk.LEFT, padx=(8, 0))
        CmdEntry = tk.Entry(
            InputFrame,
            font=("Consolas", 10),
            bg=self.Colors["bg3"],
            fg=self.Colors["text"],
            insertbackground=self.Colors["green"],
            relief="sunken",
        )
        CmdEntry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4, ipady=8)
        CmdEntry.focus_set()
        WinHistory = []
        WinHistIdx = [-1]

        def RunCmd():
            Cmd = CmdEntry.get().strip()
            if not Cmd:
                return
            WinHistory.append(Cmd)
            WinHistIdx[0] = -1
            OutputText.config(state=tk.NORMAL)
            OutputText.insert(tk.END, f"❯ {Cmd}\n", "prompt")
            self.AddLog(f"[>] #{Sid}: {Cmd}")
            try:
                Ok, Res = self.Server.ExecuteCommand(Sid, Cmd)
                if Ok:
                    OutputText.insert(tk.END, f"{Res}\n\n", "success")
                    self.AddLog(f"[<] #{Sid}: OK")
                else:
                    OutputText.insert(tk.END, f"Error: {Res}\n\n", "error")
                    self.AddLog(f"[<] #{Sid}: FAIL")
            except Exception as Error:
                OutputText.insert(tk.END, f"Exception: {Error}\n\n", "error")
                self.AddLog(f"[!] #{Sid}: {Error}")
            OutputText.see(tk.END)
            OutputText.config(state=tk.DISABLED)
            CmdEntry.delete(0, tk.END)

        def WinHistUp(E):
            if not WinHistory:
                return
            if WinHistIdx[0] == -1:
                WinHistIdx[0] = len(WinHistory) - 1
            elif WinHistIdx[0] > 0:
                WinHistIdx[0] -= 1
            CmdEntry.delete(0, tk.END)
            CmdEntry.insert(0, WinHistory[WinHistIdx[0]])

        def WinHistDown(E):
            if not WinHistory or WinHistIdx[0] == -1:
                return
            if WinHistIdx[0] < len(WinHistory) - 1:
                WinHistIdx[0] += 1
                CmdEntry.delete(0, tk.END)
                CmdEntry.insert(0, WinHistory[WinHistIdx[0]])
            else:
                WinHistIdx[0] = -1
                CmdEntry.delete(0, tk.END)

        CmdEntry.bind("<Return>", lambda E: RunCmd())
        CmdEntry.bind("<Up>", WinHistUp)
        CmdEntry.bind("<Down>", WinHistDown)
        tk.Button(
            InputFrame,
            text="Run",
            font=("Segoe UI", 9, "bold"),
            bg=self.Colors["accent"],
            fg="#fff",
            relief="sunken",
            padx=16,
            pady=6,
            command=RunCmd,
            cursor="hand2",
            activebackground="#1f6feb",
            activeforeground="#fff",
        ).pack(side=tk.RIGHT, padx=(0, 6), pady=4)

    def OnTerminalSubmit(self, Event):
        SidStr = self.TermSessionEntry.get().strip()
        Cmd = self.TerminalInput.get().strip()
        if not SidStr:
            self.TerminalWrite("[!] Enter a session ID first\n", "error")
            return
        if not Cmd:
            return
        try:
            Sid = int(SidStr)
        except ValueError:
            self.TerminalWrite("[!] Invalid session ID\n", "error")
            return
        if not self.Server:
            self.TerminalWrite("[!] Server not running\n", "error")
            return
        self.CommandHistory.append(Cmd)
        self.HistoryIndex = -1
        self.TerminalWrite(f"❯ ", "prompt")
        self.TerminalWrite(f"{Cmd}\n")
        self.AddLog(f"[>] #{Sid}: {Cmd}")
        self.TerminalInput.delete(0, tk.END)

        def ExecAsync():
            try:
                Ok, Res = self.Server.ExecuteCommand(Sid, Cmd)
                if Ok:
                    self.Root.after(
                        0, lambda: self.TerminalWrite(f"{Res}\n\n", "success")
                    )
                    self.AddLog(f"[<] #{Sid}: OK")
                else:
                    self.Root.after(
                        0, lambda: self.TerminalWrite(f"Error: {Res}\n\n", "error")
                    )
                    self.AddLog(f"[<] #{Sid}: FAIL")
            except Exception as e:
                self.Root.after(
                    0, lambda: self.TerminalWrite(f"Exception: {e}\n\n", "error")
                )
                self.AddLog(f"[!] #{Sid}: {e}")

        threading.Thread(target=ExecAsync, daemon=True).start()

    def OnHistoryUp(self, Event):
        if not self.CommandHistory:
            return "break"
        if self.HistoryIndex == -1:
            self.HistoryIndex = len(self.CommandHistory) - 1
        elif self.HistoryIndex > 0:
            self.HistoryIndex -= 1
        self.TerminalInput.delete(0, tk.END)
        self.TerminalInput.insert(0, self.CommandHistory[self.HistoryIndex])
        return "break"

    def OnHistoryDown(self, Event):
        if not self.CommandHistory or self.HistoryIndex == -1:
            return "break"
        if self.HistoryIndex < len(self.CommandHistory) - 1:
            self.HistoryIndex += 1
            self.TerminalInput.delete(0, tk.END)
            self.TerminalInput.insert(0, self.CommandHistory[self.HistoryIndex])
        else:
            self.HistoryIndex = -1
            self.TerminalInput.delete(0, tk.END)
        return "break"

    def KillSession(self):
        Sel = self.SessionTree.selection()
        if not Sel:
            messagebox.showwarning("Warning", "Select a session first")
            return
        Item = self.SessionTree.item(Sel[0])["values"]
        Sid = int(Item[0])
        Name = str(Item[2])
        if not messagebox.askyesno(
            "Confirm Kill", f"Terminate session #{Sid} ({Name})?"
        ):
            return
        self.AddLog(f"[*] Killing #{Sid} ({Name})...")
        if hasattr(self.Server, "RemoveSession"):
            self.Server.RemoveSession(Sid)
        elif hasattr(self.Server, "RemoveAgent"):
            self.Server.RemoveAgent(Sid)
        else:
            messagebox.showerror("Error", "Server does not support session removal")
            return
        self.AddLog(f"[+] #{Sid} ({Name}) killed")
        self.Toast.Show(f"Session #{Sid} terminated", "success")
        self.RefreshSessions()
        for Field in self.DetailLabels:
            self.DetailLabels[Field].config(text="—")

    def ClearTerminal(self):
        self.TerminalOutput.config(state=tk.NORMAL)
        self.TerminalOutput.delete("1.0", tk.END)
        self.TerminalOutput.config(state=tk.DISABLED)

    def ExportTerminal(self):
        FilePath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Export Terminal Output",
        )
        if not FilePath:
            return
        try:
            Content = self.TerminalOutput.get("1.0", tk.END)
            with open(FilePath, "w", encoding="utf-8") as F:
                F.write(Content)
            self.Toast.Show(f"Exported to {FilePath}", "success")
            self.AddLog(f"[+] Terminal exported: {FilePath}")
        except Exception as Error:
            messagebox.showerror("Export Error", str(Error))

    def ClearLogs(self):
        self.LogText.delete("1.0", tk.END)
        self.Logs.clear()
        self.Toast.Show("Logs cleared", "info")

    def ExportLogs(self):
        FilePath = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[
                ("Log Files", "*.log"),
                ("Text Files", "*.txt"),
                ("All Files", "*.*"),
            ],
            title="Export Logs",
        )
        if not FilePath:
            return
        try:
            with open(FilePath, "w", encoding="utf-8") as F:
                for Entry in self.Logs:
                    F.write(Entry)
            self.Toast.Show(f"Logs exported to {FilePath}", "success")
            self.AddLog(f"[+] Logs exported: {FilePath}")
        except Exception as Error:
            messagebox.showerror("Export Error", str(Error))

    def ApplyLogFilter(self):
        FilterVal = self.LogFilterVar.get()
        self.LogText.delete("1.0", tk.END)
        TagMap = {
            "success": "[+]",
            "error": "[!]",
            "warning": "[*]",
            "info": "[>]",
        }
        for Entry in self.Logs:
            if FilterVal == "all":
                Tag = None
                if "[+]" in Entry:
                    Tag = "success"
                elif "[!]" in Entry or "[-]" in Entry:
                    Tag = "error"
                elif "[*]" in Entry:
                    Tag = "warning"
                elif "[>]" in Entry or "[<]" in Entry:
                    Tag = "info"
                try:
                    TsEnd = Entry.index("]") + 1
                    self.LogText.insert(tk.END, Entry[: TsEnd + 1], "timestamp")
                    if Tag:
                        self.LogText.insert(tk.END, Entry[TsEnd + 1 :], Tag)
                    else:
                        self.LogText.insert(tk.END, Entry[TsEnd + 1 :])
                except Exception:
                    self.LogText.insert(tk.END, Entry)
            else:
                Marker = TagMap.get(FilterVal, "")
                ExtraMarker = "[-]" if FilterVal == "error" else ""
                ExtraMarker2 = "[<]" if FilterVal == "info" else ""
                if (
                    Marker in Entry
                    or (ExtraMarker and ExtraMarker in Entry)
                    or (ExtraMarker2 and ExtraMarker2 in Entry)
                ):
                    try:
                        TsEnd = Entry.index("]") + 1
                        self.LogText.insert(tk.END, Entry[: TsEnd + 1], "timestamp")
                        self.LogText.insert(tk.END, Entry[TsEnd + 1 :], FilterVal)
                    except Exception:
                        self.LogText.insert(tk.END, Entry, FilterVal)
        self.LogText.see(tk.END)

    def OnClose(self):
        if messagebox.askokcancel("Quit", "Stop server and exit?"):
            self.UpdateRunning = False
            if self.Server:
                try:
                    self.Server.StopServer()
                except Exception:
                    pass
            self.Root.destroy()

    def Run(self, Host="0.0.0.0", Port=4444, UseMTLS=False, MeterpreterMode=False):
        if not self.StartServer(Host, Port, UseMTLS, MeterpreterMode):
            return
        self.Root.mainloop()


if __name__ == "__main__":
    TOMCATC2GUI().Run()
