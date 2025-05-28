#-------------------- Imports --------------------

from abc import ABC, abstractmethod
from functools import lru_cache

import re

#-------------------- Common Passwords --------------------

@lru_cache(maxsize=1)
def get_passwords_list():
    with open("common_passwords.txt") as f:
        return set(f.read().split())

#-------------------- Validator Rules --------------------


class BaseRule(ABC):
    @abstractmethod
    def validate(self, password: str) -> bool:
        """
        Returns True is the password passes all specified rules
        """
        raise NotImplementedError
    
    @abstractmethod
    def message(self) -> str:
        """
        Returns the apporpriate Error message if validation fails
        """
        raise NotImplementedError
    
    def __str__(self):
        return self.message()
    

class MinLengthRule(BaseRule):
    def __init__(self, min_length: int = 8, message: str = None):
        self.min_length = min_length
        self._message = message

    def validate(self, password: str) -> bool:
        return len(password) >= self.min_length
    
    def message(self):
        return self._message or f"Password must be at least {self.min_length} characters long"


class MaxLengthRule(BaseRule):
    def __init__(self, max_length: int = 65, message: str = None):
        self.max_length = max_length
        self._message = message

    def validate(self, password: str) -> bool:
        return len(password) <= self.max_length
    
    def message(self):
        return self._message or f"Passwords must be under {self.max_length} characters long"


class UppercaseRule(BaseRule):
    def __init__(self, message: str = None):
        self._message = message

    def validate(self, password: str) -> bool:
        return any(c.isupper() for c in password)
    
    def message(self):
        return self._message or "Password must include at least one uppercase character"


class NumbersRule(BaseRule):
    def __init__(self, message: str = None):
        self._message = message

    def validate(self, password: str) -> bool:
        return any(c.isdigit() for c in password)
    
    def message(self):
        return self._message or "Password must include at least one digit (0 - 9)"


class SymbolsRule(BaseRule):
    def __init__(self, message: str = None):
        self._message = message

    def validate(self, password: str) -> bool:
        return bool(re.search(r"[!\"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]", password))
    
    def message(self):
        return self._message or "Password must include at least one special character/symbol"


class NoSpacesRule(BaseRule):
    def __init__(self, message: str = None):
        self._message = message

    def validate(self, password: str) -> bool:
        return not bool(re.search(r"\s", password))
    
    def message(self):
        return self._message or "Password must not include spaces"
    

class MustIncludeCharRule(BaseRule):
    def __init__(self, character: str = None, message: str = None):
        self.character = character
        self._message = message

    def validate(self, password: str) -> bool:
        return True if self.character in password else False
    
    def message(self):
        return self._message or f"Password must include the specified character: {self.character}"
    

class MostCommonPasswordsRule(BaseRule):
    def __init__(self, message: str = None):
        self._message = message

    def validate(self, password: str) -> bool:
        return password not in get_passwords_list()
    
    def message(self):
        return self._message or "Password is too common and easy to guess"