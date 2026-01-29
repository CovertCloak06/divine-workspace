# Keep Kotlin serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}

-keep,includedescriptorclasses class com.divine.specter.child.**$$serializer { *; }
-keepclassmembers class com.divine.specter.child.** {
    *** Companion;
}
-keepclasseswithmembers class com.divine.specter.child.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Keep service classes
-keep class com.divine.specter.child.service.** { *; }
-keep class com.divine.specter.child.receiver.** { *; }
