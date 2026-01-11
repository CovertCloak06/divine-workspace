package com.covertcloak.scripturealarm.data

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.io.File
import java.io.FileOutputStream

data class Book(
    val id: Int,
    val name: String,
    val abbreviation: String,
    val testament: String,
    val chapterCount: Int
)

data class Verse(
    val bookId: Int,
    val bookName: String,
    val chapter: Int,
    val verse: Int,
    val text: String
) {
    fun getReference(): String = "$bookName $chapter:$verse"
}

class BibleDatabase(private val context: Context) {

    private val dbName = "kjv_bible.db"
    private var database: SQLiteDatabase? = null

    init {
        copyDatabaseIfNeeded()
    }

    private fun copyDatabaseIfNeeded() {
        val dbFile = context.getDatabasePath(dbName)
        if (!dbFile.exists()) {
            dbFile.parentFile?.mkdirs()
            context.assets.open(dbName).use { input ->
                FileOutputStream(dbFile).use { output ->
                    input.copyTo(output)
                }
            }
        }
        database = SQLiteDatabase.openDatabase(dbFile.path, null, SQLiteDatabase.OPEN_READONLY)
    }

    fun getAllBooks(): List<Book> {
        val books = mutableListOf<Book>()
        val cursor = database?.rawQuery(
            "SELECT id, name, abbreviation, testament, chapter_count FROM books ORDER BY id",
            null
        )
        cursor?.use {
            while (it.moveToNext()) {
                books.add(Book(
                    id = it.getInt(0),
                    name = it.getString(1),
                    abbreviation = it.getString(2),
                    testament = it.getString(3),
                    chapterCount = it.getInt(4)
                ))
            }
        }
        return books
    }

    fun getOldTestamentBooks(): List<Book> = getAllBooks().filter { it.testament == "Old Testament" }

    fun getNewTestamentBooks(): List<Book> = getAllBooks().filter { it.testament == "New Testament" }

    fun getBookByName(name: String): Book? {
        val cursor = database?.rawQuery(
            "SELECT id, name, abbreviation, testament, chapter_count FROM books WHERE name = ?",
            arrayOf(name)
        )
        cursor?.use {
            if (it.moveToFirst()) {
                return Book(
                    id = it.getInt(0),
                    name = it.getString(1),
                    abbreviation = it.getString(2),
                    testament = it.getString(3),
                    chapterCount = it.getInt(4)
                )
            }
        }
        return null
    }

    fun getVerse(bookName: String, chapter: Int, verse: Int): Verse? {
        val cursor = database?.rawQuery(
            """
            SELECT v.book_id, b.name, v.chapter, v.verse, v.text
            FROM verses v
            JOIN books b ON v.book_id = b.id
            WHERE b.name = ? AND v.chapter = ? AND v.verse = ?
            """,
            arrayOf(bookName, chapter.toString(), verse.toString())
        )
        cursor?.use {
            if (it.moveToFirst()) {
                return Verse(
                    bookId = it.getInt(0),
                    bookName = it.getString(1),
                    chapter = it.getInt(2),
                    verse = it.getInt(3),
                    text = it.getString(4)
                )
            }
        }
        return null
    }

    fun getVersesInChapter(bookName: String, chapter: Int): List<Verse> {
        val verses = mutableListOf<Verse>()
        val cursor = database?.rawQuery(
            """
            SELECT v.book_id, b.name, v.chapter, v.verse, v.text
            FROM verses v
            JOIN books b ON v.book_id = b.id
            WHERE b.name = ? AND v.chapter = ?
            ORDER BY v.verse
            """,
            arrayOf(bookName, chapter.toString())
        )
        cursor?.use {
            while (it.moveToNext()) {
                verses.add(Verse(
                    bookId = it.getInt(0),
                    bookName = it.getString(1),
                    chapter = it.getInt(2),
                    verse = it.getInt(3),
                    text = it.getString(4)
                ))
            }
        }
        return verses
    }

    fun getVerseRange(bookName: String, chapter: Int, startVerse: Int, endVerse: Int): List<Verse> {
        val verses = mutableListOf<Verse>()
        val cursor = database?.rawQuery(
            """
            SELECT v.book_id, b.name, v.chapter, v.verse, v.text
            FROM verses v
            JOIN books b ON v.book_id = b.id
            WHERE b.name = ? AND v.chapter = ? AND v.verse >= ? AND v.verse <= ?
            ORDER BY v.verse
            """,
            arrayOf(bookName, chapter.toString(), startVerse.toString(), endVerse.toString())
        )
        cursor?.use {
            while (it.moveToNext()) {
                verses.add(Verse(
                    bookId = it.getInt(0),
                    bookName = it.getString(1),
                    chapter = it.getInt(2),
                    verse = it.getInt(3),
                    text = it.getString(4)
                ))
            }
        }
        return verses
    }

    fun getRandomVerse(): Verse? {
        val cursor = database?.rawQuery(
            """
            SELECT v.book_id, b.name, v.chapter, v.verse, v.text
            FROM verses v
            JOIN books b ON v.book_id = b.id
            ORDER BY RANDOM()
            LIMIT 1
            """,
            null
        )
        cursor?.use {
            if (it.moveToFirst()) {
                return Verse(
                    bookId = it.getInt(0),
                    bookName = it.getString(1),
                    chapter = it.getInt(2),
                    verse = it.getInt(3),
                    text = it.getString(4)
                )
            }
        }
        return null
    }

    fun getRandomVerseFromBook(bookName: String): Verse? {
        val cursor = database?.rawQuery(
            """
            SELECT v.book_id, b.name, v.chapter, v.verse, v.text
            FROM verses v
            JOIN books b ON v.book_id = b.id
            WHERE b.name = ?
            ORDER BY RANDOM()
            LIMIT 1
            """,
            arrayOf(bookName)
        )
        cursor?.use {
            if (it.moveToFirst()) {
                return Verse(
                    bookId = it.getInt(0),
                    bookName = it.getString(1),
                    chapter = it.getInt(2),
                    verse = it.getInt(3),
                    text = it.getString(4)
                )
            }
        }
        return null
    }

    fun getRandomVerseFromChapter(bookName: String, chapter: Int): Verse? {
        val cursor = database?.rawQuery(
            """
            SELECT v.book_id, b.name, v.chapter, v.verse, v.text
            FROM verses v
            JOIN books b ON v.book_id = b.id
            WHERE b.name = ? AND v.chapter = ?
            ORDER BY RANDOM()
            LIMIT 1
            """,
            arrayOf(bookName, chapter.toString())
        )
        cursor?.use {
            if (it.moveToFirst()) {
                return Verse(
                    bookId = it.getInt(0),
                    bookName = it.getString(1),
                    chapter = it.getInt(2),
                    verse = it.getInt(3),
                    text = it.getString(4)
                )
            }
        }
        return null
    }

    fun getRandomVerseFromTestament(testament: String): Verse? {
        val cursor = database?.rawQuery(
            """
            SELECT v.book_id, b.name, v.chapter, v.verse, v.text
            FROM verses v
            JOIN books b ON v.book_id = b.id
            WHERE b.testament = ?
            ORDER BY RANDOM()
            LIMIT 1
            """,
            arrayOf(testament)
        )
        cursor?.use {
            if (it.moveToFirst()) {
                return Verse(
                    bookId = it.getInt(0),
                    bookName = it.getString(1),
                    chapter = it.getInt(2),
                    verse = it.getInt(3),
                    text = it.getString(4)
                )
            }
        }
        return null
    }

    fun searchVerses(query: String, limit: Int = 50): List<Verse> {
        val verses = mutableListOf<Verse>()
        val cursor = database?.rawQuery(
            """
            SELECT v.book_id, b.name, v.chapter, v.verse, v.text
            FROM verses v
            JOIN books b ON v.book_id = b.id
            WHERE v.text LIKE ?
            LIMIT ?
            """,
            arrayOf("%$query%", limit.toString())
        )
        cursor?.use {
            while (it.moveToNext()) {
                verses.add(Verse(
                    bookId = it.getInt(0),
                    bookName = it.getString(1),
                    chapter = it.getInt(2),
                    verse = it.getInt(3),
                    text = it.getString(4)
                ))
            }
        }
        return verses
    }

    fun getChapterCount(bookName: String): Int {
        val cursor = database?.rawQuery(
            "SELECT chapter_count FROM books WHERE name = ?",
            arrayOf(bookName)
        )
        cursor?.use {
            if (it.moveToFirst()) {
                return it.getInt(0)
            }
        }
        return 0
    }

    fun getVerseCount(bookName: String, chapter: Int): Int {
        val cursor = database?.rawQuery(
            """
            SELECT COUNT(*) FROM verses v
            JOIN books b ON v.book_id = b.id
            WHERE b.name = ? AND v.chapter = ?
            """,
            arrayOf(bookName, chapter.toString())
        )
        cursor?.use {
            if (it.moveToFirst()) {
                return it.getInt(0)
            }
        }
        return 0
    }

    fun close() {
        database?.close()
    }

    companion object {
        @Volatile
        private var instance: BibleDatabase? = null

        fun getInstance(context: Context): BibleDatabase {
            return instance ?: synchronized(this) {
                instance ?: BibleDatabase(context.applicationContext).also { instance = it }
            }
        }
    }
}
