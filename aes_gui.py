import tkinter as tk

from main import CryptoGUI


def main():
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
