vehicles = {
    'trucks': [],
    'cars': [
        {'color': 'red',
        'build':'2024',},

        {'color': 'pink',
          'build': '2022'},
    ],
}

for car in vehicles['cars']:
    print(car['color'])
