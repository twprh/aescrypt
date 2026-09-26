import tkinter as tk

from aes_file_crypto007 import CryptoGUI


def main():
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
