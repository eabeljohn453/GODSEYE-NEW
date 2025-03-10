from sqlalchemy import create_engine, Table, Column, Integer, String, Float, MetaData

# Connect to SQLite database (creates detections.db if it doesn’t exist)
engine = create_engine('sqlite:///detections.db')
metadata = MetaData()

# Define the table
detection_detectedobject = Table(
    'detection_detectedobject', metadata,
    Column('id', Integer, primary_key=True),
    Column('frame', Integer),
    Column('class_name', String),
    Column('confidence', Float),
    Column('timestamp', Float)
)

# Create the table in the database
metadata.create_all(engine)
print("Table 'detection_detectedobject' created successfully!")