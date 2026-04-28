#  This file is part of Custodes SDC.
#
# Custodes SDC is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# Custodes SDC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with Custodes SDC. If not, see <https://www.gnu.org/licenses/>.

import argparse
import pyperclip

parser = argparse.ArgumentParser(
    prog='Copy License Header',
    description='Copy license header with selected comment specifier added.'
)

parser.add_argument('filename', help="Path to input file.")
parser.add_argument('comment_specifier', help="Comment prefix or block comment opener if --end set.")
parser.add_argument('-e', '--end', help="Block comment closer.")
parser.add_argument('-p', '--prefix', help="Block comment interior prefix.")

args = parser.parse_args()

output = ""

with open(args.filename, "r") as f:
    lines = f.readlines()

# e and p = /*\n*\n*/
# e not p = /*\n\n*/
# not e = //\n//

if args.end is not None:
    output += f'{args.comment_specifier}\n'
    if args.prefix is not None:
        prefix = f'{' ' * (len(args.comment_specifier) - len(args.prefix))}{args.prefix}'
    else:
        prefix = ''
else:
    prefix = f'{args.comment_specifier}'

for line in lines:
    output += f'{prefix} {line}'

if args.end is not None:
    output += f'\n{args.end}'

pyperclip.copy(output)