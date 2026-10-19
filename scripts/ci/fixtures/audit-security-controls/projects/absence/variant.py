import subprocess


def sibling_run():
    subprocess.run(["printf", "%s", "fixed"], check=True)
