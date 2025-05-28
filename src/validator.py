from rules import UppercaseRule, MinLengthRule, MaxLengthRule, MostCommonPasswordsRule, MustIncludeCharRule, NumbersRule, NoSpacesRule, SymbolsRule

class password_validator():
    def __init__(
        self,
        min_length=None,
        max_length=None,
        require_uppercase=False,
        require_numbers=False,
        require_symbols=False,
        no_spaces=False,
        must_include_char=None,
        not_common=False
    ):
        
    
        

    def validate(self, password: str = None):
