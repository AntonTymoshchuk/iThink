DROP TABLE IF EXISTS Users;
DROP TABLE IF EXISTS Posts;

CREATE TABLE Users (
    Id INTEGER NOT NULL UNIQUE PRIMARY KEY AUTOINCREMENT,
    Username TEXT NOT NULL UNIQUE,
    Email TEXT NOT NULL UNIQUE,
    Password TEXT NOT NULL
);

CREATE TABLE Posts (
    Id INTEGER NOT NULL UNIQUE PRIMARY KEY AUTOINCREMENT,
    Author INTEGER NOT NULL,
    Theme TEXT NOT NULL,
    Content TEXT NOT NULL,
    Created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (Author) REFERENCES Users (Id)
);