
 #Helper function to convert vector string to metric values if they are not present in the CVE data entry already
def vector_string_to_metrics(vector_string: str) -> list:
        #Defining the possible values for each score metric
        av_values = ['NETWORK', 'ADJACENT_NETWORK', 'LOCAL', 'PHYSICAL']
        ac_values = ['LOW', 'HIGH']
        privileges_required_values = ['NONE', 'LOW', 'HIGH']
        user_interaction_values = ['NONE', 'REQUIRED']
        cia_impact_values = ['NONE', 'LOW', 'HIGH']
        scope_values = ['UNCHANGED', 'CHANGED']

        #Splitting the vector string into individual metrics using ':' as separator
        metrics = vector_string.split('/')[1:]

        metrics_new = []
        for metric in metrics:
            metrics_new.append(metric.split(':'))

        #Converting the list of lists into a dictionary for easier access
        metrics_dict = dict(metrics_new)

        return  

vector_string_to_metrics("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N")
