from src import scanner


def check_file(urls):
    with open(urls, "r") as lines:
        urls_list = []
        for line in lines:
            urls_list.append(line)
        vuls = scanner.scan(urls_list)
        with open("result.txt", "a") as result:
            for item in vuls:
                result.write("{}\n".format(item))


if __name__ == '__main__':
    check_file("urls.txt")
