class Logger:
    @staticmethod
    def color_format(message: str, color: str):
        color_map = {'black': '0;30',
                     'red': '0;31',
                     'green': '0;32',
                     'orange': '0;33',
                     'blue': '0;34',
                     'yellow': '1;33',
                     'white': '1;37'}
        return '\033[{}m{}\033[0m'.format(color_map.get(color), message)

    @staticmethod
    def _message(message: str, color: str):
        print(Logger.color_format(message, color))

    @staticmethod
    def warn(message: str):
        Logger._message(message, 'orange')

    @staticmethod
    def info(message: str):
        Logger._message(message, 'green')

    @staticmethod
    def error(message: str):
        Logger._message(message, 'red')