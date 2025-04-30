import logging

class CommonLogger:
    _instances = {}
    _log_file = 'hello-ips.log'
    _handlers_configured = False
    
    def __new__(cls, name):
        if name not in cls._instances:
            cls._instances[name] = super(CommonLogger, cls).__new__(cls)
            cls._instances[name]._setup_logger(name)
        return cls._instances[name]
    
    def _setup_logger(self, name):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Only configure handlers once
        if not CommonLogger._handlers_configured:
            # Create handlers
            file_handler = logging.FileHandler(self._log_file)
            console_handler = logging.StreamHandler()
            
            # Create formatters and add it to handlers
            log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(log_format)
            console_handler.setFormatter(log_format)
            
            # Add handlers to the root logger
            root_logger = logging.getLogger()
            root_logger.addHandler(file_handler)
            root_logger.addHandler(console_handler)
            
            CommonLogger._handlers_configured = True
        
        # Initialize status callback
        self._status_callback = None
    
    def set_status_callback(self, callback):
        self._status_callback = callback
    
    def log(self, level, message):
        if self._status_callback:
            self._status_callback(message)
        getattr(self.logger, level)(message)
    
    def info(self, message):
        self.log('info', message)
    
    def warning(self, message):
        self.log('warning', message)
    
    def error(self, message):
        self.log('error', message)
    
    def debug(self, message):
        self.log('debug', message) 