import sys
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from designer import Ui_MainWindow
from cryptography import RSA
from cryptography import EIgameal
from cryptography import ECC
from cryptography import Diffie_Hellman
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import numpy as np
import random
import math

plt.ion()
plt.rcParams['font.family'] = ['SimHei']  # 用来正常显示中文标签
plt.rcParams['axes.unicode_minus'] = False  # 用来正常显示负号


class MyWindow(QMainWindow, Ui_MainWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setupUi(self)
        self.setAttribute(Qt.WA_TranslucentBackground)  # 窗体背景透明
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Tool)  # 窗口置顶，无边框，在任务栏不显示图标Qt.WindowStaysOnTopHint
        self.center()
        self.pushButton_9.clicked.connect(self.close)
        self.pushButton_6.clicked.connect(self.close)
        self.pushButton_3.clicked.connect(self.close)

        self.listWidget.itemClicked.connect(self.itemclicked_text)
        self.Button_generatekey.clicked.connect(self.Button_generatekey_clicked)
        self.Button_generatekey.clicked.connect(self.textBrower_show)
        self.buttonencrytion.clicked.connect(self.buttonRSAencryption_clicked)
        self.buttondecrytion.clicked.connect(self.buttonRSAdecryption_clicked)
        self.buttondecrytion_CRT.clicked.connect(self.buttonRSAencryption_CRT_clicked)
        # miller-rabin button
        self.pushButton.clicked.connect(self.miller_rabin_clicked)
        self.pushButton_2.clicked.connect(self.miller_rabin_clear)
        self.pushButton_4.clicked.connect(self.miller_rabin_wakeup)
        self.pushButton_5.clicked.connect(self.miller_rabin_stop)

        self.Button_generatekey_2.clicked.connect(self.Button_generatekey_clicked_2)
        self.Button_generatekey_2.clicked.connect(self.textBrower_show_EIGamal)
        self.buttonencrytion_2.clicked.connect(self.buttonEIGamalencryption_clicked)
        self.buttonencrytion_3.clicked.connect(self.buttonEIGamaldecryption_clicked)
        self.textEdit_6.setLineWrapMode(QTextEdit.NoWrap)
        self.textEdit_2.setLineWrapMode(QTextEdit.NoWrap)
        # Diffe-Hellman
        self.pushButton_10.clicked.connect(self.DH_clicked1)
        self.pushButton_8.clicked.connect(self.DH_clicked2)
        self.pushButton_7.clicked.connect(self.DH_clicked3)

        self.Button_generatekey_4.clicked.connect(self.Button_generatekey_clicked_4)
        self.Button_generatekey_4.clicked.connect(self.draw_ECC)
        self.lineEdit_3.setReadOnly(True)  # 开始设置lineEdit_3为不可编辑
        self.comboBox.currentIndexChanged.connect(self.set_lineEdit_3)
        self.buttonencrytion_4.clicked.connect(self.buttonECCencryption_clicked)
        self.buttonencrytion_5.clicked.connect(self.buttonECCdecryption_clicked)
        self.textEdit_7.setLineWrapMode(QTextEdit.NoWrap)
        self.textEdit_4.setLineWrapMode(QTextEdit.NoWrap)
        ## ECC points add
        self.pushButton_11.clicked.connect(self.Button_AllPoints_clicked)
        self.pushButton_12.clicked.connect(self.Button_Addpoints_clicked)
        self.pushButton_13.clicked.connect(self.clear_Points)

    ## ECC
    def clear_Points(self):
        self.lineEdit_24.setText(f"")
        self.lineEdit_25.setText(f"")
        self.lineEdit_26.setText(f"")
        layout = self.frame_65.layout()
        if layout is not None:
            canvas = layout.itemAt(0).widget()
            canvas.figure.clear()
        self.textEdit_3.setText(f"")

    def Button_Addpoints_clicked(self):
        self.stackedWidget_2.setCurrentIndex(0)
        if self.lineEdit_24.text() == '' or self.lineEdit_25.text() == '':
            self.lineEdit_24.setText('invail input!')
            self.lineEdit_25.setText('invail input!')
        else:
            p = eval(self.lineEdit_24.text())
            q = eval(self.lineEdit_25.text())
            # 判断p是不是列表
            if type(p) != list or (type(p) == list and (type(p[0]) != int or type(p[1]) != int)):
                self.lineEdit_24.setText('invail input!')
            if type(q) != list or (type(q) == list and (type(q[0]) != int or type(q[1]) != int)):
                self.lineEdit_25.setText('invail input!')
            else:
                if hasattr(self, 'EC') and self.EC.CurveName == "基本曲线":
                    x1, y1 = self.EC.Point_addition(p[0], p[1], q[0], q[1], self.EC.a, self.EC.p)  ## P+Q
                    x2 = x1
                    y2 = -y1 % self.EC.p  # P+Q对称点
                    self.lineEdit_26.setText(str([x1, y1]))

                    layout = self.frame_65.layout()
                    if layout is not None:
                        canvas = layout.itemAt(0).widget()  # 如果存在，就获取其中的画布对象，并调用其clear方法
                        canvas.figure.clear()
                        ax = canvas.figure.add_subplot(111)
                    else:
                        # 如果不存在，就创建一个新的画布对象，并添加到新的布局中
                        fig = plt.figure()
                        canvas = FigureCanvas(fig)  # 创建画布对象
                        canvas.setParent(self.frame_65)  # 将画布对象设置为frame_28的子控件
                        layout = QVBoxLayout()  # 创建一个垂直布局对象
                        layout.addWidget(canvas)  # 将画布对象添加到垂直布局中
                        self.frame_65.setLayout(layout)  # 将垂直布局设置为frame_28的布局
                        canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
                        ax = fig.add_subplot(111)
                    ax.scatter(p[0], p[1], color='r', marker='*')
                    ax.scatter(q[0], q[1], color='r', marker='*')
                    ax.scatter(x1, y1, color='r', marker='*')
                    ax.scatter(x2, y2, color='r', marker='*')
                    ax.text(p[0], p[1], 'P', fontsize=12)
                    ax.text(q[0], q[1], 'Q', fontsize=12)
                    ax.text(x1, y1, 'P+Q', fontsize=12)
                    # ax.text(x2, y2, f"({x2},{y2})", fontsize=12)
                    plt.subplots_adjust(left=0.15, right=0.95, top=0.99, bottom=0.15)

                    # 计算P和Q点直线的斜率
                    k = self.compute_k(p[0], p[1], q[0], q[1], self.EC.a, self.EC.p)
                    ax.axline((q[0], q[1]), slope=k, color='b', linestyle='--', linewidth=1)
                    ax.axline((p[0], p[1]), slope=k, color='b', linestyle='--', linewidth=1)
                    ax.axline((x2, y2), slope=k, color='b', linestyle='--', linewidth=1)
                    ax.axline((x2, y2), (x2, 0), color='darkorange', linestyle='--', linewidth=1)

    def compute_k(self, x1, y1, x2, y2, a, p):
        # P == Q
        if x1 == x2 and y1 == y2:
            k = ((3 * pow(x1, 2, p) + a) * self.Extended_Euclid(2 * y1, p)) % p
        # P != Q
        else:
            k = ((y1 - y2) * self.Extended_Euclid(x1 - x2, p)) % p
        return k

    def Extended_Euclid(self, x, n):
        '''Extended Euclid algorithm, Algorithm for modulo minus 1: calculates the value of x2 = x^-1 (mod n).
         :param x symbol for e is the public key
         :param n is the modulus number
        '''
        # if b == 0:
        #     return 1, 0, a
        # else:
        #     x, y, q = self.Extended_Euclid(b, a % b)
        #     print(x,y,q)
        #     x, y = y, (x - (a // b) * y)
        #     return x, y, q
        x0 = x
        y0 = n
        x1 = 0
        y1 = 1
        x2 = 1
        y2 = 0
        while n != 0:
            q = x // n
            (x, n) = (n, x % n)
            (x1, x2) = ((x2 - (q * x1)), x1)
            (y1, y2) = ((y2 - (q * y1)), y1)
        if x2 < 0:
            x2 += y0
        if y2 < 0:
            y2 += x0
        return x2

    def Button_AllPoints_clicked(self):
        self.stackedWidget_2.setCurrentIndex(1)
        if hasattr(self, 'EC') and self.EC.CurveName == "基本曲线":
            x, y = self.EC.GetPoints()
            points = []
            for i in range(len(x)):
                points.append([x[i], y[i]])
            self.textEdit_3.setText(str(points))
        elif hasattr(self, 'EC') == False:
            self.textEdit_3.setText("please generate key first!")
        else:
            self.textEdit_3.setText("please select basic curve!")

    def buttonECCencryption_clicked(self):
        message = self.textEdit_4.toPlainText()
        encode_m = self.EC.Encode(message)
        self.textEdit_7.setText(f"明文编码为: [{encode_m[0]},{encode_m[1]}]")
        self.lengthm2 = encode_m[2]
        c = self.EC.encrypt(encode_m[0], encode_m[1])
        # 判断c是否是字符串
        if isinstance(c, str):
            self.textEdit_7.setText(c)
            self.textEdit_7.append(f"明文分组为: [{encode_m[0]},{encode_m[1]}]")
            self.textEdit_7.append(f"p = {self.EC.p}")
        else:
            self.textEdit_7.append(f"r = {self.EC.r}")
            self.textEdit_7.append(f"C = {self.EC.C}")
            self.textEdit_7.append(f"Q = {self.EC.Q}")
            self.textEdit_7.append(f"密文为: [{c[0]},{c[1]},{c[2]},{c[3]}]")

    def buttonECCdecryption_clicked(self):
        c = eval(self.textEdit_4.toPlainText())
        m = self.EC.decrypt(c[0], c[1], c[2], c[3])
        self.textEdit_7.setText(f"Q = {self.EC.Q}")
        self.textEdit_7.append(f"明文分组为: [{m[0]},{m[1]}]")
        self.textEdit_7.append(f"明文为: {self.EC.Decode(m[0], m[1], self.lengthm2)}")

    def Button_generatekey_clicked_4(self):
        if self.comboBox.currentText() == "无":
            self.textBrowser_5.setText('请选择曲线类型！')

        elif self.lineEdit_3.text().isdigit() == True:
            self.EC = ECC(CurveName=self.comboBox.currentText(), bitlength=int(self.lineEdit_3.text()))
            self.textBrowser_5.setLineWrapMode(QTextEdit.NoWrap)
            self.textBrowser_5.setText(f"p = {self.EC.p}")
            self.textBrowser_5.append(f"a = {self.EC.a}")
            self.textBrowser_5.append(f"b = {self.EC.b}")
            self.textBrowser_5.append(f"G = {self.EC.G}")
            self.textBrowser_5.append(f"k = {self.EC.k}")
            self.textBrowser_5.append(f"K = {self.EC.K1}")
            self.textBrowser_5.append(
                f"Pubic Key = [({self.EC.p}, {self.EC.a}, {self.EC.b}), {self.EC.G}, {self.EC.K1}]")
            self.textBrowser_5.append(f"Private Key = [{self.EC.k}]")
        else:
            self.lineEdit_3.setText('invail input!')

    def set_lineEdit_3(self):
        text = self.comboBox.currentText()
        if text == 'secp256k1':
            self.lineEdit_3.setReadOnly(True)
            self.lineEdit_3.setText('256')
        elif text == 'secp256r1':
            self.lineEdit_3.setReadOnly(True)
            self.lineEdit_3.setText('256')
        elif text == 'sm2p256v1':
            self.lineEdit_3.setReadOnly(True)
            self.lineEdit_3.setText('256')
        elif text == 'secp384r1':
            self.lineEdit_3.setReadOnly(True)
            self.lineEdit_3.setText('384')
        elif text == 'secp521r1':
            self.lineEdit_3.setReadOnly(True)
            self.lineEdit_3.setText('512')
        elif text == '基本曲线':
            self.lineEdit_3.setReadOnly(False)
            self.lineEdit_3.setText('')
        else:
            self.lineEdit_3.setReadOnly(True)
            self.lineEdit_3.setText('')

    def draw_ECC(self):
        if self.comboBox.currentText() == '基本曲线' and self.lineEdit_3.text().isdigit() == True:
            layout = self.frame_28.layout()
            if layout is not None:
                canvas = layout.itemAt(0).widget()  # 如果存在，就获取其中的画布对象，并调用其clear方法
                canvas.figure.clear()
                ax = canvas.figure.add_subplot(111)
            else:
                # 如果不存在，就创建一个新的画布对象，并添加到新的布局中
                fig = plt.figure()
                canvas = FigureCanvas(fig)  # 创建画布对象
                canvas.setParent(self.frame_28)  # 将画布对象设置为frame_28的子控件
                layout = QVBoxLayout()  # 创建一个垂直布局对象
                layout.addWidget(canvas)  # 将画布对象添加到垂直布局中
                self.frame_28.setLayout(layout)  # 将垂直布局设置为frame_28的布局
                canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
                ax = fig.add_subplot(111)
            x, y = self.EC.GetPoints()
            ax.plot(x, y, '.')
            ax.scatter(self.EC.G[0], self.EC.G[1], color='red')
            ax.text(self.EC.G[0], self.EC.G[1], 'G', fontsize=15, color='red')
            plt.subplots_adjust(left=0.10, right=0.95, top=0.99, bottom=0.10)  # 调整子图间距
            canvas.draw()
        # 清除画布
        else:
            layout = self.frame_28.layout()
            if layout is not None:
                canvas = layout.itemAt(0).widget()
                canvas.figure.clear()

    ## ECC

    ## EIgamal
    def Button_generatekey_clicked_2(self):
        message = self.lineEdit_2.text()
        if message.isdigit():
            self.E = EIgameal(int(message))
        else:
            self.lineEdit_2.setText('invail input!')

    def textBrower_show_EIGamal(self):
        if self.lineEdit_2.text().isdigit():
            self.textBrowser_3.setLineWrapMode(QTextEdit.NoWrap)
            self.textBrowser_3.setText(f"q = {self.E.q}")
            self.textBrowser_3.append(f"a = {self.E.a}")
            self.textBrowser_3.append(f"d = {self.E.d}")
            self.textBrowser_3.append(f"e = {self.E.e}")
            self.textBrowser_3.append(f"Pubic Key = [{self.E.q}, {self.E.a}, {self.E.e}]")
            self.textBrowser_3.append(f"Private Key = [{self.E.d}]")
        else:
            self.textBrowser_3.setText('')

    def buttonEIGamalencryption_clicked(self):
        if self.textEdit_2.toPlainText() != '':
            message = self.E.encrypt(self.textEdit_2.toPlainText())
            # 如果message是str
            if isinstance(message, str):
                self.textEdit_6.setText(message)
            else:
                self.textEdit_6.setText(f"r = {message[2]}")
                self.textEdit_6.append(f"[C1,C2] = [{message[0]}, {message[1]}]")

        else:
            self.textEdit_6.setText('')

    def buttonEIGamaldecryption_clicked(self):
        if self.textEdit_2.toPlainText() != '':
            C = eval(self.textEdit_2.toPlainText())
            if type(C) == list and type(C[0]) == int and type(C[1]) == int:
                message = self.E.decrypt(C[0], C[1])
                self.textEdit_6.setText(f"{message}")
            else:
                self.textEdit_6.setText('')
        else:
            self.textEdit_6.setText('')

    def DH_clicked1(self):
        if self.lineEdit_23.text().isdigit():
            bitlength = int(self.lineEdit_23.text())
            self.DH = Diffie_Hellman(bitlength)
            self.lineEdit_15.setText(f"{self.DH.q}")
            self.lineEdit_16.setText(f"{self.DH.a}")
        else:
            self.lineEdit_23.setText('invail input!')

    def DH_clicked2(self):
        if hasattr(self, 'DH'):
            self.lineEdit_17.setText(f"{self.DH.Alice_Privatekey()}")
            app.processEvents()
            time.sleep(1)
            self.lineEdit_18.setText(f"{self.DH.Alice_Publickey()}")
        else:
            self.lineEdit_17.setText('q and a are None!')

    def DH_clicked3(self):
        if hasattr(self, 'DH'):
            self.lineEdit_19.setText(f"{self.DH.Bob_Privatekey()}")
            app.processEvents()
            time.sleep(1)
            self.lineEdit_20.setText(f"{self.DH.Bob_Publickey()}")
            app.processEvents()
            time.sleep(1)
            self.lineEdit_21.setText(f"{self.DH.A_shared_key()}")
            self.lineEdit_22.setText(f"{self.DH.B_shared_key()}")
        else:
            self.lineEdit_19.setText('q and a are None!')

    ## EIgamal

    ## RSA
    def miller_rabin_clicked(self):
        if self.lineEdit_14.text().isdigit():
            t = int(self.lineEdit_14.text())
            n = int(self.lineEdit_13.text())
            s = 0
            k = n - 1
            while k % 2 == 0:
                k = k // 2
                s += 1
            self.lineEdit_4.setText(f"{s}")
            self.lineEdit_5.setText(f"{k}")
            if n % 2 != 0:
                self.thead = miller_thead(t, n, s, k)
                self.thead.sinout.connect(self.miller_show1)
                self.thead.sinout1.connect(self.miller_show2)
                self.thead.sinout2.connect(self.miller_show3)
                self.thead.start()
            else:
                self.lineEdit_11.setText("0.00")
        else:
            self.lineEdit_14.setText("invail input!")

    def miller_show1(self, message):
        self.lineEdit_8.setText(message[0])
        self.lineEdit_6.setText(message[1])
        self.lineEdit_7.setText(message[2])
        self.lineEdit_9.setText(message[3])

    def miller_show2(self, message):
        self.lineEdit_12.setText(message[0])
        self.lineEdit_10.setText(message[1])

    def miller_show3(self, message):
        self.lineEdit_11.setText(message[0])

    def miller_rabin_clear(self):
        self.lineEdit_4.setText("")
        self.lineEdit_5.setText("")
        self.lineEdit_8.setText("")
        self.lineEdit_6.setText("")
        self.lineEdit_7.setText("")
        self.lineEdit_9.setText("")
        self.lineEdit_12.setText("")
        self.lineEdit_10.setText("")
        self.lineEdit_11.setText("")

    def miller_rabin_stop(self):
        self.thead.pause()

    def miller_rabin_wakeup(self):
        self.thead.resume()

    def buttonRSAencryption_clicked(self):
        if self.textEdit.toPlainText() != '':
            message = self.R.encrypt(self.textEdit.toPlainText())
            self.textEdit_5.setText(f"{message}")
        else:
            self.textEdit_5.setText('')

    def buttonRSAdecryption_clicked(self):
        if self.textEdit.toPlainText() != '' and self.textEdit.toPlainText().isdigit():
            message = self.R.decrypt(int(self.textEdit.toPlainText()))
            self.textEdit_5.setText(f"{message}")
        else:
            self.textEdit_5.setText('')

    def buttonRSAencryption_CRT_clicked(self):
        if self.textEdit.toPlainText() != '' and self.textEdit.toPlainText().isdigit():
            message = self.R.decrypt_CRT(int(self.textEdit.toPlainText()))
            self.textEdit_5.setText(f"{message[0]}")

            self.textBrowser_2.setLineWrapMode(QTextEdit.NoWrap)
            self.textBrowser_2.setText(f"dp = {message[1]}")
            self.textBrowser_2.append(f"dq = {message[2]}")
            self.textBrowser_2.append(f"inv_p = {message[3]}")
            self.textBrowser_2.append(f"inv_q = {message[4]}")
            self.textBrowser_2.append(f"x1 = {message[5]}")
            self.textBrowser_2.append(f"x2 = {message[6]}")
        else:
            self.textEdit_5.setText('')
            self.textBrowser_2.setText('')

    def Button_generatekey_clicked(self):
        message = self.lineEdit.text()
        if message.isdigit():
            self.R = RSA(int(message))
        else:
            self.lineEdit.setText('invail input!')

    def textBrower_show(self):
        if self.lineEdit.text().isdigit():
            self.textBrowser.setLineWrapMode(QTextEdit.NoWrap)
            self.textBrowser.setText(f"p = {self.R.p} \nq = {self.R.q}")
            self.textBrowser.append(f"n = {self.R.n}")
            self.textBrowser.append(f"e = {self.R.e}")
            self.textBrowser.append(f"d = {self.R.d}")
            self.textBrowser.append(f"Pubic Key = [{self.R.e}, {self.R.n}]")
            self.textBrowser.append(f"Private Key = [{self.R.d}, {self.R.n}]")
        else:
            self.textBrowser.setText('')

    ## RSA

    def itemclicked_text(self, item):
        if item.text() == 'RSA':
            self.stackedWidget.setCurrentIndex(0)
        if item.text() == 'EIGamal':
            self.stackedWidget.setCurrentIndex(2)
        if item.text() == 'ECC':
            self.stackedWidget.setCurrentIndex(1)
        if item.text() == '设置':
            pass

    # 无边框的拖动  指定拖动标题区域移动
    def mouseMoveEvent(self, e: QMouseEvent):  # 重写移动事件
        if (e.x() >= 0 and e.x() <= 1400 and e.y() >= 0 and e.y() < 100):
            self._endPos = e.pos() - self._startPos
            self.move(self.pos() + self._endPos)

    def mousePressEvent(self, e: QMouseEvent):
        if e.button() == Qt.LeftButton:
            self._startPos = QPoint(e.x(), e.y())
            self._tracking = True

    def mouseReleaseEvent(self, e: QMouseEvent):
        if e.button() == Qt.LeftButton:
            self._tracking = False
            self._startPos = None
            self._endPos = None

    def center(self):
        screen = QDesktopWidget().screenGeometry()
        size = self.geometry()
        newLeft = (screen.width() - size.width()) / 2
        newTop = (screen.height() - size.height()) / 2
        self.move(int(newLeft), int(newTop))


class miller_thead(QThread):
    sinout = pyqtSignal(list)  # 自定义信号，执行run()函数时，从相关线程发射此信号
    sinout1 = pyqtSignal(list)
    sinout2 = pyqtSignal(list)

    def __init__(self, t, n, s, k):
        super(miller_thead, self).__init__()
        self.t = t
        self.n = n
        self.s = s
        self.k = k
        self._isPause = False
        self.cond = QWaitCondition()
        self.mutex = QMutex()

    def pause(self):
        self._isPause = True

    def resume(self):
        self._isPause = False
        self.cond.wakeAll()

    def run(self):
        flag = True
        message = []
        for num in range(1, self.t + 1):
            self.mutex.lock()  # 加锁
            if self._isPause:
                self.cond.wait(self.mutex)
            message.clear()
            b = random.randint(2, self.n - 1)
            g = math.gcd(b, self.n)
            message.append(f"{num}")
            message.append(f"{b}")
            message.append(f"{g}")
            if g > 1:
                flag = False
                message.append(f"")
                self.sinout.emit(message)
                break
            z = pow(b, self.k, self.n)
            message.append(f"{z}")
            print(message)
            if z == 1 or z == self.n - 1:
                self.sleep(2)
                self.sinout.emit(message)
                self.mutex.unlock()
                continue
            self.sinout.emit(message)
            self.sleep(self.s - 1)

            index = []
            for val in range(1, self.s):
                index.clear()
                z = pow(z, 2, self.n)
                index.append(f"{val}")
                index.append(f"{z}")
                self.sinout1.emit(index)
                if z == self.n - 1:
                    self.sleep(1)
                    break
                self.sleep(1)
            else:
                flag = False
                break
            self.mutex.unlock()  ## 解锁
        if flag:
            self.sinout2.emit([f"{1 - 1 / 4 ** self.t}"[0:5]])
        else:
            self.sinout2.emit([f"{0}"])


if __name__ == "__main__":
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)
    app = QApplication(sys.argv)
    mainWindow = MyWindow()
    mainWindow.show()
    sys.exit(app.exec_())
