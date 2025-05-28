from rules import UppercaseRule, MinLengthRule, MaxLengthRule, MostCommonPasswordsRule, MustIncludeCharRule, NumbersRule, NoSpacesRule, SymbolsRule
from mode import Mode

class PasswordValidator:
    def __init__(
        self,
        min_length=None,
        max_length=None,
        require_uppercase=False,
        require_numbers=False,
        require_symbols=False,
        no_spaces=False,
        must_include_char=None,
        not_common=False,
        mode=None
    ):
        self.rules = []

        if mode == Mode.lenient:
            min_length = 8
            max_length = 65
            require_uppercase = False
            require_numbers = False
            require_symbols = False
            no_spaces = False
            must_include_char = None
            not_common = False

        elif mode == Mode.moderate:
            min_length = 8
            max_length = 65
            require_uppercase = True
            require_numbers = True
            require_symbols = False
            no_spaces = True
            must_include_char = None
            not_common = False
            
        elif mode == Mode.strict:
            min_length = 12
            max_length = 65
            require_uppercase = True
            require_numbers = True
            require_symbols = True
            no_spaces = True
            must_include_char = None
            not_common = True

        if min_length is not None:
            self.rules.append(MinLengthRule(min_length=min_length))
        
        if max_length is not None:
            self.rules.append(MaxLengthRule(max_length=max_length))

        if require_uppercase:
            self.rules.append(UppercaseRule())

        if require_numbers:
            self.rules.append(NumbersRule())

        if require_symbols:
            self.rules.append(SymbolsRule())

        if no_spaces:
            self.rules.append(NoSpacesRule())

        if must_include_char is not None:
            self.rules.append(MustIncludeCharRule(character=must_include_char))

        if not_common:
            self.rules.append(MostCommonPasswordsRule())

    def validate(self, password: str = None):
        errors = [
            {"code": rule.code, "message": rule.message()}
            for rule in self.rules if not rule.validate(password)
        ]
        return len(errors) == 0, errors
