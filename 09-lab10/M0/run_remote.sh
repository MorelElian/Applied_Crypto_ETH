#!/bin/sh

# Nombre d'exécutions
num_runs=30
success_count=0

# Boucle pour exécuter le script 30 fois
for i in $(seq 1 $num_runs); do
    echo "Execution $i:"
    
    # Exécuter le script Python et capturer la sortie
    output=$(python3 remote.py)
    
    # Obtenir la dernière ligne de la sortie
    last_line=$(echo "$output" | tail -n 1)
    
    # Vérifier si la dernière ligne est égale à 'flag{test_flag}'
    if [ "$last_line" = "flag{but_they_were_all_of_them_deceived_for_a_small_subgroup_was_made44ad63e403a163d7b6272f5eb5fbf3be}" ]; then
        echo "Success: The last line of the output is 'flag{test_flag}'."
        success_count=$((success_count + 1))
    else
        echo "Error: The last line of the output is not 'flag{test_flag}'."
        echo "Actual last line: $last_line"
        echo "Full output:"
        echo "$output"
    fi
done

# Afficher le nombre de succès
echo "Number of successes: $success_count out of $num_runs"