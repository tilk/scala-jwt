scalaVersion in ThisBuild := "2.12.1"
crossScalaVersions in ThisBuild := Seq("2.11.8", "2.12.1")

import ReleaseTransformations._

releaseProcess := Seq[ReleaseStep](
  checkSnapshotDependencies,
  inquireVersions,
  runClean,
  runTest,
  setReleaseVersion,
  commitReleaseVersion,
  tagRelease,
  ReleaseStep(action = Command.process("publishSigned", _)),
  setNextVersion,
  commitNextVersion,
  ReleaseStep(action = Command.process("sonatypeReleaseAll", _)),
  pushChanges
)

val jwt = project.in(file("."))
    .settings(
        name := "Scala JWT",
        normalizedName := "scala-jwt",
        libraryDependencies ++= Seq(
            "io.circe" %% "circe-core" % "0.6.0",
            "io.circe" %% "circe-generic" % "0.6.0",
            "io.circe" %% "circe-parser" % "0.6.0",
            "com.typesafe.akka" %% "akka-actor" % "2.4.12",
            "com.typesafe.akka" %% "akka-http-core" % "10.0.1"
        ),
        organization := "eu.tilk",
        version := "0.0.1-SNAPSHOT",
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

