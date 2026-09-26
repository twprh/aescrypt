import multiprocessing

from aes_file_crypto007 import run_cli


def main():
    multiprocessing.freeze_support()
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
