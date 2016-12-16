scalaVersion in ThisBuild := "2.11.8"

val jwt = project.in(file("."))
    .settings(
        name := "Scala JWT",
        normalizedName := "scala-jwt",
        libraryDependencies ++= Seq(
            "io.circe" %% "circe-core" % "0.6.0",
            "io.circe" %% "circe-generic" % "0.6.0",
            "io.circe" %% "circe-parser" % "0.6.0",
            "com.typesafe.akka" %% "akka-actor" % "2.4.12",
            "com.typesafe.akka" %% "akka-http-core" % "3.0.0-RC1"
//            "org.typelevel" %%% "cats" % "0.8.1"
//            "com.lihaoyi" %%% "fastparse-byte" % "0.4.1",
//            "org.scalaz" %%% "scalaz-core" % "7.2.7",
//            "org.scalatest" %% "scalatest" % "3.0.0" % "test"
        ),
        organization := "org.tilk",
        version := "0.0.1-SNAPSHOT",
        scalaVersion := "2.11.8",
        licenses += ("LGPL 3.0", url("https://opensource.org/licenses/LGPL-3.0")),
        scmInfo := Some(ScmInfo(
            url("https://github.com/tilk/scala-jwt"),
            "scm:git:git@github.com:tilk/scala-jwt.git",
            Some("scm:git:git@github.com:tilk/scala-jwt.git"))),
        publishTo := {
          val nexus = "https://oss.sonatype.org/"
          if (isSnapshot.value)
            Some("snapshots" at nexus + "content/repositories/snapshots")
          else
            Some("releases" at nexus + "service/local/staging/deploy/maven2")
        },
        publishMavenStyle := true,
        pomExtra := (
          <developers>
            <developer>
              <id>tilk</id>
              <name>Marek Materzok</name>
              <url>https://github.com/tilk/</url>
            </developer>
          </developers>
        )
    )

