/*
 * Copyright 2012 The Error Prone Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.errorprone.bugpatterns;

import static com.google.errorprone.matchers.Matchers.allOf;
import static com.google.errorprone.matchers.Matchers.anyOf;
import static com.google.errorprone.matchers.Matchers.enclosingMethod;
import static com.google.errorprone.matchers.Matchers.instanceMethod;
import static com.google.errorprone.matchers.Matchers.methodIsNamed;
import static com.google.errorprone.matchers.Matchers.not;

import com.google.errorprone.BugPattern;
import com.google.errorprone.BugPattern.SeverityLevel;
import com.google.errorprone.VisitorState;
import com.google.errorprone.annotations.DangerouslySuppressBanSerializable;
import com.google.errorprone.annotations.SuppressBanSerializableCompletedSecurityReview;
import com.google.errorprone.annotations.SuppressBanSerializableForLegacyCode;
import com.google.errorprone.bugpatterns.BugChecker.MethodInvocationTreeMatcher;
import com.google.errorprone.fixes.SuggestedFix;
import com.google.errorprone.matchers.Description;
import com.google.errorprone.matchers.Matcher;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.MethodInvocationTree;

/** A {@link BugChecker} that detects use of the unsafe {@link java.io.Serializable} API. */
@BugPattern(
    name = "BanSerializableRead",
    summary = "You used an unsafe `Serializable` API",
    explanation =
        "Java serialization is dangerous. Any consumption of a serialized object that"
            + "cannot be explicitly trusted will likely result in a critical "
            + "remote code execution bug, allowing control over the application. "
            + "Consider using less powerful serialization methods, such as JSON, protobuf or XML",
    severity = SeverityLevel.ERROR,
    suppressionAnnotations = {
      DangerouslySuppressBanSerializable.class,
      SuppressBanSerializableCompletedSecurityReview.class,
      SuppressBanSerializableForLegacyCode.class
    })
public final class BanSerializableRead extends BugChecker implements MethodInvocationTreeMatcher {

  /** Checks for unsafe deserialization calls on an ObjectInputStream in an ExpressionTree. */
  private static final Matcher<ExpressionTree> ObjectInputStream_Deserialize_Matcher =
      allOf(
          // this matches calls to the ObjectInputStream to read some objects
          instanceMethod()
              .onDescendantOf("java.io.ObjectInputStream")
              .namedAnyOf(
                  // Prevent reading objects unsafely into memory
                  "readObject",

                  // This is the same, the default value
                  "defaultReadObject",

                  // This is for trusted subclasses
                  "readObjectOverride",

                  // Ultimately, a lot of the safety worries come
                  // from being able to construct arbitrary classes via
                  // reading in class descriptors. I don't think anyone
                  // will bother calling this directly, but I don't see
                  // any reason not to block it.
                  "readClassDescriptor",

                  // These are basically the same as above
                  "resolveClass",
                  "resolveObject"),

          // Java lets you override or add to the default deserialization behaviour
          // by defining a 'readObject' on your class. In this case, it's super common
          // to see calls to deserialize methods (after all, it's what *would* happen
          // if it *were* deserialized). We specifically want to allow such members to
          // be defined, but never called
          not(enclosingMethod(methodIsNamed("readObject"))));

  /** Checks for unsafe uses of the Java deserialization API. */
  private static final Matcher<ExpressionTree> MATCHER =
      anyOf(
          // This excludes cases *inside* a Serializable.readObject method, so...
          ObjectInputStream_Deserialize_Matcher,
          // this blocks actual calls to Serializable.readObject
          instanceMethod().onDescendantOf("java.io.Serializable").named("readObject"));

  @Override
  public Description matchMethodInvocation(MethodInvocationTree tree, VisitorState state) {
    if (MATCHER.matches(tree, state)) {
      return describeMatch(
          tree,
          SuggestedFix.prefixWith(tree, "@" + DangerouslySuppressBanSerializable.class.getName()));
    }

    return Description.NO_MATCH;
  }
}
