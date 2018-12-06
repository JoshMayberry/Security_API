import lazyLoad
lazyLoad.load(
	"Cryptodome",
)

#Import the controller module as this namespace
from .controller import *
del controller