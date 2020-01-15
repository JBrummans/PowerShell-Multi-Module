# multi-module

## Original Creator:
- JBrummans
- https://github.com/JBrummans/

Feel free to reach out and chat about this module :)

## Description:
Collection of functions for use within a Windows Domain Enviroment. Module contains custom and sourced code.

## Naming Conventions:
All functions must adhere to the naming convenetion `(Verb)-MM(Noun)` where Verb is a standard Powershell verb and Noun can be anything describing the function.

Verb list can be found by running `Get-Verb` in powershell.
The inclusion of `-MM` in the function name is to ensure unique naming among other Microsoft/Third-Party functions.

## Requirements for new functions:
Must include comment based help within the function. (See: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comment_based_help?view=powershell-6)
If a large portion of code has been sourced, list the source under the Synopsis using the `.LINK` keyword.
Provide examples using `.EXAMPLE` if suitable.

##  Tips:
Module should be saved to the "USERNAME\Documents\WindowsPowerShell\Modules\Multi-Module\" folder.
Run `Get-Command -Module Multi-Module` in powershell to get a list of all functions within the module.
Alternatively run `Get-MMInfo` in powershell to list all functions in this module and display the synopsis of each.
Run `Get-Help FUNCTIONNAME -full` to show detailed help for a function.
Run `Get-Help FUNCTIONNAME -examples` to show examples for the function (if included in the comment based help).

## Contributing
If you wish to make an addition/modification to this module, please make a pull request.
