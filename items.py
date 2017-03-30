
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import json
from database_setup import Category, Base, Item, User


engine = create_engine('sqlite:///catalogitem.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

json_data = open("item.json").read()
jsonData = json.loads(json_data)


# Create user

User1 = User(name=jsonData['user']['name'], email=jsonData[
             'user']['email'], picture=jsonData['user']['picture'])
session.add(User1)
session.commit()
print ("added user!")

# Create category Items
for categories in jsonData['categories']:
    for category in categories:
        Category1 = Category(user_id=User1.id, name=category['name'])
        session.add(Category1)
        session.commit()
print ("added categories!")

for categories in jsonData['categories']:
    for category in categories:
        for items in category['items']:
            item1 = Item(user_id=User1.id, name=items['name'], type=items['type'], description=items[
                         'description'], price=items['price'], category=Category1)
            session.add(item1)
            session.commit()
print ("added items!")
