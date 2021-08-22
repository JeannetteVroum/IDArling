from subprocess import run
from os import chdir, getcwd


base = getcwd()

print("### Begin of script ###")
print("[+] Build docker pour idarling")
# idarling
chdir("idarling/idarling")
run("docker build -t jeannetteblini/idarling .")
chdir(base)
print("[+] Done.")
print("[+] Build docker pour idarling_management")
# idarling_management
chdir("idarling_management/idarling_management")
run("docker build -t jeannetteblini/idarling_management .")
chdir(base)
print("[+] Done.")
print("### End of script ###")