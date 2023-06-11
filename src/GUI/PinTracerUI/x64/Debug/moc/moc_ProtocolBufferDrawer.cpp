/****************************************************************************
** Meta object code from reading C++ file 'ProtocolBufferDrawer.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.5.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../include/widgets/protocol/ProtocolBufferDrawer.h"
#include <QtCore/qmetatype.h>

#if __has_include(<QtCore/qtmochelpers.h>)
#include <QtCore/qtmochelpers.h>
#else
QT_BEGIN_MOC_NAMESPACE
#endif


#include <memory>

#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'ProtocolBufferDrawer.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.5.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {

#ifdef QT_MOC_HAS_STRINGDATA
struct qt_meta_stringdata_CLASSProtocolBufferDrawerENDCLASS_t {};
static constexpr auto qt_meta_stringdata_CLASSProtocolBufferDrawerENDCLASS = QtMocHelpers::stringData(
    "ProtocolBufferDrawer",
    "signalShowBufferByteContextMenu",
    "",
    "std::vector<std::shared_ptr<PROTOCOL::ProtocolByte>>",
    "chosenBytes",
    "sendRequestShowBufferByteContextMenu",
    "pos",
    "PROTOCOL::ByteBufferPushButton*",
    "button",
    "actionShowBufferBytesContextMenu",
    "bytes"
);
#else  // !QT_MOC_HAS_STRING_DATA
struct qt_meta_stringdata_CLASSProtocolBufferDrawerENDCLASS_t {
    uint offsetsAndSizes[22];
    char stringdata0[21];
    char stringdata1[32];
    char stringdata2[1];
    char stringdata3[53];
    char stringdata4[12];
    char stringdata5[37];
    char stringdata6[4];
    char stringdata7[32];
    char stringdata8[7];
    char stringdata9[33];
    char stringdata10[6];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_CLASSProtocolBufferDrawerENDCLASS_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_CLASSProtocolBufferDrawerENDCLASS_t qt_meta_stringdata_CLASSProtocolBufferDrawerENDCLASS = {
    {
        QT_MOC_LITERAL(0, 20),  // "ProtocolBufferDrawer"
        QT_MOC_LITERAL(21, 31),  // "signalShowBufferByteContextMenu"
        QT_MOC_LITERAL(53, 0),  // ""
        QT_MOC_LITERAL(54, 52),  // "std::vector<std::shared_ptr<P..."
        QT_MOC_LITERAL(107, 11),  // "chosenBytes"
        QT_MOC_LITERAL(119, 36),  // "sendRequestShowBufferByteCont..."
        QT_MOC_LITERAL(156, 3),  // "pos"
        QT_MOC_LITERAL(160, 31),  // "PROTOCOL::ByteBufferPushButton*"
        QT_MOC_LITERAL(192, 6),  // "button"
        QT_MOC_LITERAL(199, 32),  // "actionShowBufferBytesContextMenu"
        QT_MOC_LITERAL(232, 5)   // "bytes"
    },
    "ProtocolBufferDrawer",
    "signalShowBufferByteContextMenu",
    "",
    "std::vector<std::shared_ptr<PROTOCOL::ProtocolByte>>",
    "chosenBytes",
    "sendRequestShowBufferByteContextMenu",
    "pos",
    "PROTOCOL::ByteBufferPushButton*",
    "button",
    "actionShowBufferBytesContextMenu",
    "bytes"
};
#undef QT_MOC_LITERAL
#endif // !QT_MOC_HAS_STRING_DATA
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_CLASSProtocolBufferDrawerENDCLASS[] = {

 // content:
      11,       // revision
       0,       // classname
       0,    0, // classinfo
       3,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,   32,    2, 0x06,    1 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       5,    2,   35,    2, 0x08,    3 /* Private */,
       9,    1,   40,    2, 0x08,    6 /* Private */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3,    4,

 // slots: parameters
    QMetaType::Void, QMetaType::QPoint, 0x80000000 | 7,    6,    8,
    QMetaType::Void, 0x80000000 | 3,   10,

       0        // eod
};

Q_CONSTINIT const QMetaObject ProtocolBufferDrawer::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_CLASSProtocolBufferDrawerENDCLASS.offsetsAndSizes,
    qt_meta_data_CLASSProtocolBufferDrawerENDCLASS,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_CLASSProtocolBufferDrawerENDCLASS_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<ProtocolBufferDrawer, std::true_type>,
        // method 'signalShowBufferByteContextMenu'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<std::vector<std::shared_ptr<PROTOCOL::ProtocolByte>>, std::false_type>,
        // method 'sendRequestShowBufferByteContextMenu'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QPoint &, std::false_type>,
        QtPrivate::TypeAndForceComplete<PROTOCOL::ByteBufferPushButton *, std::false_type>,
        // method 'actionShowBufferBytesContextMenu'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<std::vector<std::shared_ptr<PROTOCOL::ProtocolByte>>, std::false_type>
    >,
    nullptr
} };

void ProtocolBufferDrawer::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ProtocolBufferDrawer *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->signalShowBufferByteContextMenu((*reinterpret_cast< std::add_pointer_t<std::vector<std::shared_ptr<PROTOCOL::ProtocolByte>>>>(_a[1]))); break;
        case 1: _t->sendRequestShowBufferByteContextMenu((*reinterpret_cast< std::add_pointer_t<QPoint>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<PROTOCOL::ByteBufferPushButton*>>(_a[2]))); break;
        case 2: _t->actionShowBufferBytesContextMenu((*reinterpret_cast< std::add_pointer_t<std::vector<std::shared_ptr<PROTOCOL::ProtocolByte>>>>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType(); break;
        case 1:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType(); break;
            case 1:
                *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType::fromType< PROTOCOL::ByteBufferPushButton* >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ProtocolBufferDrawer::*)(std::vector<std::shared_ptr<PROTOCOL::ProtocolByte>> );
            if (_t _q_method = &ProtocolBufferDrawer::signalShowBufferByteContextMenu; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
    }
}

const QMetaObject *ProtocolBufferDrawer::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ProtocolBufferDrawer::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CLASSProtocolBufferDrawerENDCLASS.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int ProtocolBufferDrawer::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    }
    return _id;
}

// SIGNAL 0
void ProtocolBufferDrawer::signalShowBufferByteContextMenu(std::vector<std::shared_ptr<PROTOCOL::ProtocolByte>> _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
