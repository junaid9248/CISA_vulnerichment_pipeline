def vector_string_to_metrics(vector_string: str) -> dict:
    # Defining the possible values for each score metric
    basescoremetrics = {
        'attack_vector': '',
        'attack_complexity': '',
        'privileges_required': '',
        'user_interaction': '',
        'scope': '',
        'confidentiality_impact': '',
        'integrity_impact': '',
        'availability_impact': '',
    }  
    
    # Splitting the vector string into individual metrics using ':' as separator
    metrics = vector_string.split('/')[1:]
    
    metrics_new = []
    for metric in metrics:
        metrics_new.append(metric.split(':'))
    
    # Converting the list of lists into a dictionary for easier access
    metrics_dict = dict(metrics_new)
    print(f"Metrics dict: {metrics_dict}")
    
    # Parse each metric
    match metrics_dict.get('AV'):
        case 'N': basescoremetrics['attack_vector'] = 'NETWORK'
        case 'A': basescoremetrics['attack_vector'] = 'ADJACENT_NETWORK'
        case 'L': basescoremetrics['attack_vector'] = 'LOCAL'
        case 'P': basescoremetrics['attack_vector'] = 'PHYSICAL'
        case _: basescoremetrics['attack_vector'] = ''
    
    match metrics_dict.get('AC'):
        case 'L': basescoremetrics['attack_complexity'] = 'LOW'
        case 'H': basescoremetrics['attack_complexity'] = 'HIGH'
        case _: basescoremetrics['attack_complexity'] = ''
    
    match metrics_dict.get('PR'):
        case 'N': basescoremetrics['privileges_required'] = 'NONE'
        case 'L': basescoremetrics['privileges_required'] = 'LOW'
        case 'H': basescoremetrics['privileges_required'] = 'HIGH'
        case _: basescoremetrics['privileges_required'] = ''
    
    match metrics_dict.get('UI'):
        case 'N': basescoremetrics['user_interaction'] = 'NONE'
        case 'R': basescoremetrics['user_interaction'] = 'REQUIRED'
        case _: basescoremetrics['user_interaction'] = ''
    
    match metrics_dict.get('S'):
        case 'U': basescoremetrics['scope'] = 'UNCHANGED'
        case 'C': basescoremetrics['scope'] = 'CHANGED'
        case _: basescoremetrics['scope'] = ''
    
    match metrics_dict.get('C'):
        case 'N': basescoremetrics['confidentiality_impact'] = 'NONE'
        case 'L': basescoremetrics['confidentiality_impact'] = 'LOW'
        case 'H': basescoremetrics['confidentiality_impact'] = 'HIGH'
        case _: basescoremetrics['confidentiality_impact'] = ''
    
    match metrics_dict.get('I'):
        case 'N': basescoremetrics['integrity_impact'] = 'NONE'
        case 'L': basescoremetrics['integrity_impact'] = 'LOW'
        case 'H': basescoremetrics['integrity_impact'] = 'HIGH'
        case _: basescoremetrics['integrity_impact'] = ''
    
    match metrics_dict.get('A'):
        case 'N': basescoremetrics['availability_impact'] = 'NONE'
        case 'L': basescoremetrics['availability_impact'] = 'LOW'
        case 'H': basescoremetrics['availability_impact'] = 'HIGH'
        case _: basescoremetrics['availability_impact'] = ''
    
    return basescoremetrics

# Test the function
result = vector_string_to_metrics("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N")
print(result)