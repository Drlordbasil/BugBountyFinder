from PyQt5.QtWidgets import QWidget
from PyQt5.QtCore import QTimer, Qt, QRectF
from PyQt5.QtGui import QPainter, QColor, QPen

class LoadingSpinner(QWidget):
    def __init__(self, parent=None, size=40, line_width=4, color=QColor(0, 135, 189), speed=50):
        super().__init__(parent)
        self.angle = 0
        self.size = size
        self.line_width = line_width
        self.color = color
        self.speed = speed
        
        self.setFixedSize(size, size)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.rotate)
        self.timer.start(speed)

    def rotate(self):
        self.angle = (self.angle + 30) % 360
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.translate(self.width() / 2, self.height() / 2)
        painter.rotate(self.angle)
        
        painter.setPen(QPen(self.color, self.line_width, Qt.SolidLine, Qt.RoundCap))
        rect = QRectF(-self.size/2 + self.line_width/2, -self.size/2 + self.line_width/2,
                      self.size - self.line_width, self.size - self.line_width)
        painter.drawArc(rect, 0, 300 * 16)

    def start(self):
        self.timer.start(self.speed)

    def stop(self):
        self.timer.stop()

    def setColor(self, color):
        self.color = color
        self.update()

    def setSpeed(self, speed):
        self.speed = speed
        self.timer.setInterval(speed)
