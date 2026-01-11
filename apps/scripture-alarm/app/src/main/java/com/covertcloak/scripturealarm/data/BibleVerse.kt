package com.covertcloak.scripturealarm.data

data class BibleVerse(
    val book: String,
    val chapter: Int,
    val verse: Int,
    val text: String,
    val category: VerseCategory = VerseCategory.GENERAL
) {
    val reference: String
        get() = "$book $chapter:$verse"
}

enum class VerseCategory {
    GENERAL,
    MORNING,
    ENCOURAGEMENT,
    GOSPEL_MATTHEW,
    GOSPEL_MARK,
    GOSPEL_LUKE,
    GOSPEL_JOHN,
    PSALMS,
    PROVERBS
}

object BibleVerseRepository {

    private val verses = listOf(
        // Morning verses
        BibleVerse("Psalm", 118, 24, "This is the day that the Lord has made; let us rejoice and be glad in it.", VerseCategory.MORNING),
        BibleVerse("Lamentations", 3, 22, "The steadfast love of the Lord never ceases; his mercies never come to an end; they are new every morning; great is your faithfulness.", VerseCategory.MORNING),
        BibleVerse("Psalm", 5, 3, "In the morning, Lord, you hear my voice; in the morning I lay my requests before you and wait expectantly.", VerseCategory.MORNING),
        BibleVerse("Psalm", 143, 8, "Let the morning bring me word of your unfailing love, for I have put my trust in you. Show me the way I should go, for to you I entrust my life.", VerseCategory.MORNING),

        // Encouragement
        BibleVerse("Joshua", 1, 9, "Have I not commanded you? Be strong and courageous. Do not be afraid; do not be discouraged, for the Lord your God will be with you wherever you go.", VerseCategory.ENCOURAGEMENT),
        BibleVerse("Isaiah", 41, 10, "So do not fear, for I am with you; do not be dismayed, for I am your God. I will strengthen you and help you; I will uphold you with my righteous right hand.", VerseCategory.ENCOURAGEMENT),
        BibleVerse("Philippians", 4, 13, "I can do all things through Christ who strengthens me.", VerseCategory.ENCOURAGEMENT),
        BibleVerse("Romans", 8, 28, "And we know that in all things God works for the good of those who love him, who have been called according to his purpose.", VerseCategory.ENCOURAGEMENT),
        BibleVerse("Jeremiah", 29, 11, "For I know the plans I have for you, declares the Lord, plans to prosper you and not to harm you, plans to give you hope and a future.", VerseCategory.ENCOURAGEMENT),

        // Psalms
        BibleVerse("Psalm", 23, 1, "The Lord is my shepherd; I shall not want.", VerseCategory.PSALMS),
        BibleVerse("Psalm", 27, 1, "The Lord is my light and my salvation; whom shall I fear? The Lord is the stronghold of my life; of whom shall I be afraid?", VerseCategory.PSALMS),
        BibleVerse("Psalm", 46, 1, "God is our refuge and strength, a very present help in trouble.", VerseCategory.PSALMS),
        BibleVerse("Psalm", 91, 1, "He who dwells in the shelter of the Most High will abide in the shadow of the Almighty.", VerseCategory.PSALMS),
        BibleVerse("Psalm", 121, 1, "I lift up my eyes to the hills. From where does my help come? My help comes from the Lord, who made heaven and earth.", VerseCategory.PSALMS),

        // Proverbs
        BibleVerse("Proverbs", 3, 5, "Trust in the Lord with all your heart and lean not on your own understanding; in all your ways submit to him, and he will make your paths straight.", VerseCategory.PROVERBS),
        BibleVerse("Proverbs", 16, 3, "Commit to the Lord whatever you do, and he will establish your plans.", VerseCategory.PROVERBS),
        BibleVerse("Proverbs", 4, 23, "Above all else, guard your heart, for everything you do flows from it.", VerseCategory.PROVERBS),

        // Gospel of Matthew
        BibleVerse("Matthew", 5, 14, "You are the light of the world. A city set on a hill cannot be hidden.", VerseCategory.GOSPEL_MATTHEW),
        BibleVerse("Matthew", 6, 33, "But seek first the kingdom of God and his righteousness, and all these things will be added to you.", VerseCategory.GOSPEL_MATTHEW),
        BibleVerse("Matthew", 11, 28, "Come to me, all you who are weary and burdened, and I will give you rest.", VerseCategory.GOSPEL_MATTHEW),
        BibleVerse("Matthew", 28, 20, "And behold, I am with you always, to the end of the age.", VerseCategory.GOSPEL_MATTHEW),

        // Gospel of Mark
        BibleVerse("Mark", 10, 27, "Jesus looked at them and said, 'With man it is impossible, but not with God. For all things are possible with God.'", VerseCategory.GOSPEL_MARK),
        BibleVerse("Mark", 11, 24, "Therefore I tell you, whatever you ask in prayer, believe that you have received it, and it will be yours.", VerseCategory.GOSPEL_MARK),

        // Gospel of Luke
        BibleVerse("Luke", 1, 37, "For nothing will be impossible with God.", VerseCategory.GOSPEL_LUKE),
        BibleVerse("Luke", 6, 31, "Do to others as you would have them do to you.", VerseCategory.GOSPEL_LUKE),
        BibleVerse("Luke", 12, 32, "Fear not, little flock, for it is your Father's good pleasure to give you the kingdom.", VerseCategory.GOSPEL_LUKE),

        // Gospel of John
        BibleVerse("John", 3, 16, "For God so loved the world, that he gave his only Son, that whoever believes in him should not perish but have eternal life.", VerseCategory.GOSPEL_JOHN),
        BibleVerse("John", 14, 6, "Jesus said to him, 'I am the way, and the truth, and the life. No one comes to the Father except through me.'", VerseCategory.GOSPEL_JOHN),
        BibleVerse("John", 14, 27, "Peace I leave with you; my peace I give to you. Not as the world gives do I give to you. Let not your hearts be troubled, neither let them be afraid.", VerseCategory.GOSPEL_JOHN),
        BibleVerse("John", 16, 33, "I have said these things to you, that in me you may have peace. In the world you will have tribulation. But take heart; I have overcome the world.", VerseCategory.GOSPEL_JOHN),

        // General
        BibleVerse("1 Corinthians", 16, 13, "Be on your guard; stand firm in the faith; be courageous; be strong.", VerseCategory.GENERAL),
        BibleVerse("2 Timothy", 1, 7, "For God gave us a spirit not of fear but of power and love and self-control.", VerseCategory.GENERAL),
        BibleVerse("Hebrews", 11, 1, "Now faith is the assurance of things hoped for, the conviction of things not seen.", VerseCategory.GENERAL),
        BibleVerse("1 Peter", 5, 7, "Cast all your anxiety on him because he cares for you.", VerseCategory.GENERAL),
        BibleVerse("Colossians", 3, 23, "Whatever you do, work heartily, as for the Lord and not for men.", VerseCategory.GENERAL)
    )

    private var currentIndex = 0

    fun getRandomVerse(): BibleVerse {
        return verses.random()
    }

    fun getRandomVerse(category: VerseCategory): BibleVerse {
        val filtered = verses.filter { it.category == category }
        return if (filtered.isNotEmpty()) filtered.random() else getRandomVerse()
    }

    fun getNextVerse(): BibleVerse {
        val verse = verses[currentIndex]
        currentIndex = (currentIndex + 1) % verses.size
        return verse
    }

    fun getVersesByCategory(category: VerseCategory): List<BibleVerse> {
        return verses.filter { it.category == category }
    }

    fun getAllCategories(): List<VerseCategory> = VerseCategory.entries
}
