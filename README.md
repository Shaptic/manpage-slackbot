# ManMan, the Man Page Slack Bot #
This friendly bot will link to the online version of the man page for most (if not all) Linux API functions. The mapping is created from Michael Kerrisk's fantastic [_man-pages_ project](https://www.kernel.org/doc/man-pages/); it's generated from [this list](http://man7.org/linux/man-pages/dir_all_alphabetic.html).

The bot will respond with a link if it is explicitly mentioned with a message matching the pattern `man [function]`. If the function is found, it responds with the link; if it isn't, the bot will let you know. :)

### Usage ###
> user [03:40]  
> **@man** can I have man sem_overview, please?

> Man Bot APP [03:40]  
> `sem_overview`: [http://man7.org/linux/man-pages/man7/sem_overview.7.html](http://man7.org/linux/man-pages/man7/sem_overview.7.html)

This project was hacked together over the course of a few hours. It's licensed to all under the [WTF public license](http://www.wtfpl.net/). 
