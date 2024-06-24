

import sys
import re
import xml.etree.ElementTree as ET

jumps = 0
unique_labels = 0
labels_array = []

def defined_labels(name,defined_labels_array,order):

    if name not in defined_labels_array:
        defined_labels_array.append(f"{name},{order}")

def frequenci(array, opcode):
    found = False

    for i, item in enumerate(array):
        if item.startswith(opcode + ','):
            # Found ? -> increment count of it.
            item_count = int(item.split(',')[1])
            item_count += 1
            array[i] = f"{opcode},{item_count}"
            found = True
            break

    if not found:
        # Ddidnt find then add to array.
        array.append(f"{opcode},1")

def is_unique_label(labels_name):
    global unique_labels
    global labels_array

    if labels_name not in labels_array:
        labels_array.append(labels_name)
        unique_labels +=1

def parse_line(line, comments):
    if "#" in line:  
        comments += 1  # counter of comments.
    line = line.split('#', 1)[0].strip()
    if not line:
        return None, comments  
    tokens = re.split(r'\s+', line)
    return tokens, comments  # Return token and comments.

def is_valid_var(args):
    # Regex for var.
    if re.match(r'^(GF|LF|TF)@[a-zA-Z_\-$&%*!?][a-zA-Z0-9_\-$&%*!?]*$', args):
        return True
    else:
        print("Invalid var")
        sys.exit(23)

def is_valid_type(value):
    # Allowed types.
    allowed_types = ['int', 'bool', 'string', 'nil']
    return value in allowed_types

def is_valid_label(label):
    # Regex for label.
    label_pattern = r'^[a-zA-Z_\-$&%*!?][a-zA-Z0-9_\-$&%*!?]*$'
    
    return bool(re.match(label_pattern, label))

def is_valid_symbol(symbol):
    # Regex for symbol

    symbol_pattern = r'^(int@-?(?:0x[\dA-Fa-f]+|0o[0-7]+|\d+)|bool@(true|false)|nil@nil|string@((?:[^\x00-\x1F#\s\\]|\\[0-9]{3})*))$'

    # Its symbol.
    if re.match(symbol_pattern, symbol):
        return True
    # Its var.
    elif is_valid_var(symbol) == True:
        return True
    else:
        print("Invalid symbol")
        sys.exit(23)

# We generate xml instruction with its proper type and arguments.  
def generate_xml_instruction(root, opcode, args, order):
    instruction = ET.SubElement(root, "instruction", order=str(order), opcode=opcode)
    for i, arg in enumerate(args, start=1):

        if (opcode == "JUMPIFEQ" or opcode == "JUMPIFNEQ") and i == 1:
            arg_type = "label"
            arg_content = arg

        elif opcode == "LABEL" or opcode == "JUMP" or opcode == "CALL": 
            arg_type = "label"
            arg_content = arg

        elif arg.startswith(('GF@', 'LF@', 'TF@')):
            arg_type = "var"
            arg_content = arg 

        elif arg.startswith(('bool@', 'int@', 'nil@', 'string@')):
            arg_type, arg_content = arg.split('@', 1)
        
        elif arg in ['int', 'bool', 'string', 'nil', 'label', 'type', 'var']:
            arg_type = "type"  
            arg_content = arg
        
        arg_element = ET.SubElement(instruction, f"arg{i}", type=arg_type)
        arg_element.text = arg_content

def validate_instruction(opcode,args,order,root,array,defined_labels_array,array_of_jumps,array_of_all_labels):

    # Switch case for matching opcode and then checking its arguments.
    global jumps

    frequenci(array,opcode)

    if opcode == "MOVE" or opcode == "NOT" :
        if len(args) == 2:
            is_valid_var(args[0])
            is_valid_symbol(args[1])
            
            generate_xml_instruction(root, opcode, args, order)
            return True
        else:
            print(f"Wrong count of arguments at opcod: {opcode}")
            sys.exit(23)
        
    elif opcode == "POPFRAME" or opcode == "RETURN" or opcode == "PUSHFRAME" or opcode == "CREATEFRAME" or opcode == "BREAK":
        if len(args) == 0:
            if opcode == "RETURN":
                jumps +=1
            generate_xml_instruction(root, opcode, args, order)
            return True
        else:
            print(f"Wrong count of arguments at opcod: {opcode}")
            sys.exit(23)
    
    elif opcode == "DEFVAR" or opcode == "POPS":
        if len(args) == 1:
            is_valid_var(args[0])
            
            generate_xml_instruction(root, opcode, args, order)
            return True
        else:
            print(f"Wrong count of arguments at opcod: {opcode}")
            sys.exit(23)
    
    elif opcode == "CALL" or opcode == "LABEL" or opcode == "JUMP":
        if len(args) == 1:
            if (is_valid_label(args[0]) == True):
                is_unique_label(args[0])
                if opcode == "CALL" or opcode == "JUMP":
                    array_of_jumps.append(f"{args[0]},{order}")
                    jumps +=1
                elif opcode == "LABEL":
                    defined_labels(args[0],defined_labels_array,order)
                    array_of_all_labels.append(f"{args[0]},{order}")
                generate_xml_instruction(root, opcode, args, order)
                return True
            else:
                print(f"Invalid label at opcode: {opcode}")
                sys.exit(23)
        else:
            print(f"Wrong count of arguments at opcod: {opcode}")
            sys.exit(23)
            
    elif opcode == "PUSHS" or opcode == "WRITE" or opcode == "EXIT" or opcode == "DPRINT":
        if len(args) == 1:
            is_valid_symbol(args[0])
            
            generate_xml_instruction(root, opcode, args, order)
            return True
        else:
            print(f"Wrong count of arguments at opcode: {opcode}")
            sys.exit(23)

    elif opcode == "ADD" or opcode == "SUB" or opcode == "MUL" or opcode == "IDIV" or opcode == "LT" or opcode == "GT" or\
          opcode == "EQ" or opcode == "AND" or opcode == "OR" or opcode == "STRI2INT" or\
            opcode == "CONCAT" or opcode == "GETCHAR" or opcode == "SETCHAR":
        if len(args) == 3:
            is_valid_var(args[0])
            is_valid_symbol(args[1])
            is_valid_symbol(args[2])
            
            generate_xml_instruction(root, opcode, args, order)
            return True
        else:
            print(f"Wrong count of arguments at opcod: {opcode}")
            sys.exit(23)         
        
    elif opcode == "INT2CHAR" or opcode == "STRLEN" or opcode == "TYPE":
        if len(args) == 2:
            is_valid_var(args[0])
            is_valid_symbol(args[1])
            
            generate_xml_instruction(root, opcode, args, order)
            return True
        else:
            print(f"Wrong count of arguments at opcod: {opcode}")
            sys.exit(23)

    elif opcode == "READ":
        if len(args) == 2:
            is_valid_var(args[0])
            condition = is_valid_type(args[1])
            if(condition == True):
                
                generate_xml_instruction(root, opcode, args, order)
                return True
            else:
                print(f"Type is not valid at opcode: {opcode}")
                sys.exit(23)
        else:
            print(f"Wrong count of arguments at opcode: {opcode}")
            sys.exit(23)
       
    elif opcode == "JUMPIFEQ" or opcode == "JUMPIFNEQ":
        
        if len(args) == 3:
            
            if(is_valid_label(args[0]) == True):
                is_unique_label(args[0])
                is_valid_symbol(args[1])
                is_valid_symbol(args[2])
                jumps += 1
                array_of_jumps.append(f"{args[0]},{order}")
                generate_xml_instruction(root, opcode, args, order)
                return True
            else:
                print(f"Label is not valid at opcode: {opcode}")
                sys.exit(23)
        else:
            print(f"Wrong count of arguments at opcode: {opcode}")
            sys.exit(23)
    
    else:
        print("wrong form of opcode")
        sys.exit(22)

def get_count(item):
    return int(item.split(',')[1])

def compare_arrays(defined_labels_array):
    global labels_array
    counter_of_bad_labels = 0
    
    defined_labels_names = [label.split(',')[0] for label in defined_labels_array]

    for label in labels_array:
        label_name = label.split(',')[0]
        if label_name not in defined_labels_names:
            counter_of_bad_labels += 1
    
    return counter_of_bad_labels

def count_forward_jumps(array_of_all_labels, array_of_jumps,bfjump):

    jumps_counter = 0
    
    for jump in array_of_jumps:
        jump_name, jump_order = jump.split(',')
        jump_order = int(jump_order)
        
        for label in array_of_all_labels:
            label_name, label_order = label.split(',')
            label_order = int(label_order)
            
            # Counter of fowards jumps
            if jump_name == label_name and label_order < jump_order and bfjump == False:
                jumps_counter += 1
            # Counter of back jumps
            elif jump_name == label_name and label_order > jump_order and bfjump == True:
                jumps_counter +=1   

    return jumps_counter

def main():

    loc_counter = 0

    if "--help" in sys.argv:
        if len(sys.argv) > 2:
            print("--help cannot be combined with other arguments.")
            sys.exit(10)
        print("""This script is run by commad python3 parse.py 
You can combine with other arguments as --help.
This program read from standart input file U can execute
it like python3 parse.py < input.txt
U can also print output to stdout with command 
python3 parse.py < input.txt > output.txt
This script also supports stats which mean that It will print out
statistics of some instruction.
To run stats u can do it by adding argument --stats=[file.txt]
File that is right after --stats= is the one where it will show results.
If u run any of the stats argument without --stats then it will display error.
Here are the adding arguments u can add for stats:
--loc -> lines of code
--comments -> count of comments
--frequent -> frequency of opcodes and its count of use.
--labels -> number of labels.
--jumps -> number of jumps.
--fwjumps -> number of fowards jumps.
--backjumps -> number of back jumps.
--badjumps -> number of jumps to undefined label.
--print=['string'] -> print the string of your choice.
--eol -> eol count.
            """)
        sys.exit(0)
       
    root = ET.Element("program", language="IPPcode24")
    
    input_lines = sys.stdin.readlines()

    if not input_lines:
        print("Empty file")
        sys.exit(21)

    first_valid = False
    order = 1
    comments = 0
    # Array of opcodes
    array = []
    # Array for defined labels
    defined_labels_array = []
    # array with jumps name and his order
    array_of_jumps = []
    # array with labels name and his order
    array_of_all_labels = []

    for line in input_lines:
        
        tokens, comments = parse_line(line, comments)
       
        if tokens is None:  # If parsing line returns none, then we get next line
            continue
        
        if not first_valid:  # Check if it's the first valid line
            if tokens[0] != ".IPPcode24":
                print("Missing head .IPPcode24")
                sys.exit(21)
            first_valid = True
            continue
        
        
        opcode = tokens[0].upper()
        args = tokens[1:]

        if opcode == ".IPPCODE24":
            sys.exit(23)

        if validate_instruction(opcode,args,order,root,array,defined_labels_array,array_of_jumps,array_of_all_labels):

            order += 1  # Increment order for next instruction
            loc_counter += 1
        else:
            print("Multiple .IPPcode24 or some other mistake")
            
    
    # Generate xml instructions
    ET.indent(root)
    tree = ET.ElementTree(root)
    tree.write(sys.stdout, encoding="unicode", xml_declaration=True)

    # Sort opcode by frequenci
    array.sort(key=get_count, reverse=True)
    
    # Get count of bad jumps
    count_of_bad_jumps = compare_arrays(defined_labels_array)
    # Get count of fwjumps
    count_of_fwjumps = count_forward_jumps(array_of_all_labels,array_of_jumps,True)
    #Get count of back jumps
    count_of_backjumps = count_forward_jumps(array_of_all_labels,array_of_jumps,False)

    # Array for storing file names.
    file_array = []

    # Variabile to store actuall file to print out answers
    stats_file = None

    arguments = sys.argv[1:]

    
    if not arguments or arguments[0].startswith("--stats="):

        # Loop trough stats arguments.
        for argument in arguments:

            if argument.startswith("--stats="):
                stats_file_path = argument.split("=")[1]
                if stats_file_path in file_array:
                    print(f"File {stats_file_path} was already created.")
                    sys.exit(12)
                else:
                    file_array.append(stats_file_path)  # Append the file name to the file_array
                    stats_file = open(stats_file_path, "w")

            elif argument == "--frequent":
                stats_file.write(",".join([item.split(',')[0] for item in array]).upper() + "\n")

            elif argument == "--loc":
                stats_file.write(f"{loc_counter}\n")

            elif argument == "--comments":
                stats_file.write(f"{comments}\n")             
                
            elif argument == "--labels":
                stats_file.write(f"{unique_labels}\n")

            elif argument == "--jumps":
                stats_file.write(f"{jumps}\n")

            elif argument == "--fwjumps":
                stats_file.write(f"{count_of_fwjumps}\n")

            elif argument == "--backjumps":
                stats_file.write(f"{count_of_backjumps}\n")

            elif argument == "--badjumps":
                stats_file.write(f"{count_of_bad_jumps}\n")

            elif argument.startswith("--print="):
                string_to_print = argument.split("=", 1)[1]
                stats_file.write(f"{string_to_print}\n")

            elif argument == "--eol":
                stats_file.write(f"\n")
            else:
                sys.exit(10)
    else:
        print("Error, missing --stats")
        sys.exit(13)


if __name__ == "__main__":
    main()
    sys.exit(0)
