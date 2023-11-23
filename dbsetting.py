from sqlalchemy import create_engine

engine = create_engine('sqlite:///./test.db')

with engine.connect() as conn:
    conn.execute('create table if not exists test (id integer primary key, name text)')

    result = conn.execute('select * from test')
    for row in result:
        print(row)
