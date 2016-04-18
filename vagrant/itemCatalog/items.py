
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

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


# Create dummy user
User1 = User(name="Manpreet Singh", email="singhmanpreet1980@gmail.com",
             picture='https://media.licdn.com/mpr/mpr/shrinknp_200_200/p/2/005/07a/0a7/1c6dad8.jpg')
session.add(User1)
session.commit()

# Items for Cricket
Category1 = Category(user_id=1, name="Cricket")

session.add(Category1)
session.commit()

Item2 = Item(user_id=1, name="SS Gladiator", type="Cricket bat", description="English willow",
                     price="$200.50", category=Category1)

session.add(Item2)
session.commit()


Item1 = Item(user_id=1, name="SS leg guards",  type="Cricket leg guard", description="light weight leg guards for batting",
                     price="$35.99", category=Category1)

session.add(Item1)
session.commit()

# Items for Field Hockey
Category2 = Category(user_id=1, name="Field Hockey")

session.add(Category2)
session.commit()

Item2 = Item(user_id=1, name="Protos hockey stick", type="Hockey stick", description="English willow",
                     price="$100.50", category=Category2)

session.add(Item2)
session.commit()


Item1 = Item(user_id=1, name="Protos Hockey leg guards", type="Hockey leg guards", description="light weight leg guards for Goal keeper",
                     price="$35.99", category=Category2)

session.add(Item1)
session.commit()

print "added items!"