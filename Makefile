CC = cl.exe
CFLAGS = /c /TC /I includes
LINK = link.exe
NAME = loader
LFLAGS = /MACHINE:x86 /OUT:$(NAME)

SRCS = src/main.c \
	   src/reader.c \
	   src/loader.c \
	   src/utils.c

OBJS = main.obj reader.obj loader.obj utils.obj

all:
	$(CC) $(CFLAGS) $(SRCS)
	$(LINK) $(OBJS) $(LFLAGS).exe

build_lib:
	lib.exe $(LFLAGS).lib $(OBJS) kernel32.lib msvcrt.lib

clean:
	del $(OBJS) /S /Q

fclean:
	del $(OBJS) /S /Q
	del $(NAME).exe /S /Q
	del $(NAME).lib /S /Q