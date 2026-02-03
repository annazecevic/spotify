-- Kreiranje keyspace-a za notifikacije
CREATE KEYSPACE IF NOT EXISTS notifications
WITH replication = {
    'class': 'SimpleStrategy',
    'replication_factor': 1
};

USE notifications;

-- Kreiranje tabele za notifikacije
-- Particiona se po user_id, sortira po created_at (DESC)
CREATE TABLE IF NOT EXISTS notifications (
    id uuid,
    user_id text,
    type text,
    message text,
    title text,
    created_at timestamp,
    read boolean,
    artist_id text,
    genre_id text,
    album_id text,
    track_id text,
    PRIMARY KEY (user_id, created_at, id)
) WITH CLUSTERING ORDER BY (created_at DESC);

-- Kreiranje indeksa za brže pretraživanje po tipu notifikacije
CREATE INDEX IF NOT EXISTS idx_notification_type ON notifications (type);

-- Primer podataka za testiranje
-- Korisnik user123
INSERT INTO notifications (id, user_id, type, message, title, created_at, read, artist_id, album_id)
VALUES (uuid(), 'f2bf500b-3e23-43e3-97b4-3569e8ecb671', 'NEW_ALBUM', 'Nov album "Greatest Hits" umetnika The Beatles je objavljen!', 'Novi album', toTimestamp(now()), false, 'artist1', 'album1');

INSERT INTO notifications (id, user_id, type, message, title, created_at, read, artist_id, track_id)
VALUES (uuid(), 'f2bf500b-3e23-43e3-97b4-3569e8ecb671', 'NEW_TRACK', 'Nova pesma "Let It Be" umetnika The Beatles je dostupna!', 'Nova pesma', toTimestamp(now()), false, 'artist1', 'track1');

INSERT INTO notifications (id, user_id, type, message, title, created_at, read, genre_id, artist_id)
VALUES (uuid(), 'f2bf500b-3e23-43e3-97b4-3569e8ecb671', 'NEW_ARTIST', 'Novi umetnik "Pink Floyd" u žanru Rock je dodat!', 'Novi umetnik', toTimestamp(now()), false, 'genre1', 'artist2');

INSERT INTO notifications (id, user_id, type, message, title, created_at, read, artist_id, album_id)
VALUES (uuid(), 'user123', 'NEW_ALBUM', 'Nov album "Abbey Road" umetnika The Beatles je objavljen!', 'Novi album', '2026-01-14 10:00:00+0000', true, 'artist1', 'album2');

-- Korisnik user456
INSERT INTO notifications (id, user_id, type, message, title, created_at, read, artist_id, track_id)
VALUES (uuid(), 'user456', 'NEW_TRACK', 'Nova pesma "Bohemian Rhapsody" umetnika Queen je dostupna!', 'Nova pesma', toTimestamp(now()), false, 'artist3', 'track2');

INSERT INTO notifications (id, user_id, type, message, title, created_at, read, genre_id, artist_id)
VALUES (uuid(), 'user456', 'NEW_ARTIST', 'Novi umetnik "Led Zeppelin" u žanru Rock je dodat!', 'Novi umetnik', '2026-01-15 09:00:00+0000', false, 'genre1', 'artist4');

-- Korisnik testuser
INSERT INTO notifications (id, user_id, type, message, title, created_at, read, artist_id, album_id)
VALUES (uuid(), 'testuser', 'NEW_ALBUM', 'Nov album "Dark Side of the Moon" umetnika Pink Floyd je objavljen!', 'Novi album', toTimestamp(now()), false, 'artist2', 'album3');

INSERT INTO notifications (id, user_id, type, message, title, created_at, read, artist_id, track_id)
VALUES (uuid(), 'testuser', 'NEW_TRACK', 'Nova pesma "Stairway to Heaven" umetnika Led Zeppelin je dostupna!', 'Nova pesma', '2026-01-15 08:00:00+0000', false, 'artist4', 'track3');

INSERT INTO notifications (id, user_id, type, message, title, created_at, read, genre_id, artist_id)
VALUES (uuid(), 'testuser', 'NEW_ARTIST', 'Novi umetnik "The Rolling Stones" u žanru Rock je dodat!', 'Novi umetnik', '2026-01-15 07:00:00+0000', true, 'genre1', 'artist5');

