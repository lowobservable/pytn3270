import unittest

import context

from tn3270.attributes import Attribute

class AttributeTestCase(unittest.TestCase):
    def test_protected(self):
        # Act
        attribute = Attribute(0b00100000)

        # Assert
        self.assertTrue(attribute.protected)
        self.assertFalse(attribute.numeric)
        self.assertFalse(attribute.skip)
        self.assertFalse(attribute.intensified)
        self.assertFalse(attribute.hidden)
        self.assertFalse(attribute.modified)

    def test_numeric(self):
        # Act
        attribute = Attribute(0b00010000)

        # Assert
        self.assertFalse(attribute.protected)
        self.assertTrue(attribute.numeric)
        self.assertFalse(attribute.skip)
        self.assertFalse(attribute.intensified)
        self.assertFalse(attribute.hidden)
        self.assertFalse(attribute.modified)

    def test_skip(self):
        # Act
        attribute = Attribute(0b00110000)

        # Assert
        self.assertTrue(attribute.protected)
        self.assertTrue(attribute.numeric)
        self.assertTrue(attribute.skip)
        self.assertFalse(attribute.intensified)
        self.assertFalse(attribute.hidden)
        self.assertFalse(attribute.modified)

    def test_intensified(self):
        # Act
        attribute = Attribute(0b00001000)

        # Assert
        self.assertFalse(attribute.protected)
        self.assertFalse(attribute.numeric)
        self.assertFalse(attribute.skip)
        self.assertTrue(attribute.intensified)
        self.assertFalse(attribute.hidden)
        self.assertFalse(attribute.modified)

    def test_hidden(self):
        # Act
        attribute = Attribute(0b00001100)

        # Assert
        self.assertFalse(attribute.protected)
        self.assertFalse(attribute.numeric)
        self.assertFalse(attribute.skip)
        self.assertFalse(attribute.intensified)
        self.assertTrue(attribute.hidden)
        self.assertFalse(attribute.modified)

    def test_modified(self):
        # Act
        attribute = Attribute(0b00000001)

        # Assert
        self.assertFalse(attribute.protected)
        self.assertFalse(attribute.numeric)
        self.assertFalse(attribute.skip)
        self.assertFalse(attribute.intensified)
        self.assertFalse(attribute.hidden)
        self.assertTrue(attribute.modified)
